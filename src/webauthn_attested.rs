use std::{collections::HashSet, io::Cursor};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ciborium::{Value, value::CanonicalValue};
use p256::{ecdsa::VerifyingKey, pkcs8::EncodePublicKey};

use crate::{PaKeyError, Result};

const FIXED_AUTH_DATA: usize = 37;
const ATTESTED_HEADER: usize = 18;
const MAX_CREDENTIAL_ID: usize = 1023;

/// Binds browser convenience fields to attested credential data before staging.
pub(crate) fn verify_attested_credential(
    authenticator: &[u8],
    credential_id_b64url: &str,
    public_key_spki_b64url: &str,
) -> Result<()> {
    if authenticator.len() < FIXED_AUTH_DATA + ATTESTED_HEADER || authenticator[32] & 0x40 == 0 {
        return Err(PaKeyError::UserVerification);
    }
    let id_length = usize::from(u16::from_be_bytes([authenticator[53], authenticator[54]]));
    let id_start = FIXED_AUTH_DATA + ATTESTED_HEADER;
    let key_start = id_start
        .checked_add(id_length)
        .filter(|_| id_length > 0 && id_length <= MAX_CREDENTIAL_ID)
        .ok_or(PaKeyError::UserVerification)?;
    let id = authenticator
        .get(id_start..key_start)
        .ok_or(PaKeyError::UserVerification)?;
    if URL_SAFE_NO_PAD
        .decode(credential_id_b64url)
        .map_err(|_| PaKeyError::UserVerification)?
        != id
    {
        return Err(PaKeyError::UserVerification);
    }
    let encoded = authenticator
        .get(key_start..)
        .ok_or(PaKeyError::UserVerification)?;
    let key_length = verify_cose_public_key(encoded, public_key_spki_b64url)?;
    verify_extensions(encoded, key_length, authenticator[32] & 0x80 != 0)?;
    Ok(())
}

fn verify_cose_public_key(encoded: &[u8], public_key_spki_b64url: &str) -> Result<usize> {
    let mut cursor = Cursor::new(encoded);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| PaKeyError::UserVerification)?;
    let consumed = usize::try_from(cursor.position()).map_err(|_| PaKeyError::UserVerification)?;
    let Value::Map(entries) = value else {
        return Err(PaKeyError::UserVerification);
    };
    verify_canonical_map(
        &entries,
        encoded
            .get(..consumed)
            .ok_or(PaKeyError::UserVerification)?,
    )?;
    let integer = |label| {
        cose_value(&entries, label)
            .and_then(Value::as_integer)
            .map(i128::from)
    };
    let browser = URL_SAFE_NO_PAD
        .decode(public_key_spki_b64url)
        .map_err(|_| PaKeyError::UserVerification)?;
    match (integer(1), integer(3)) {
        (Some(2), Some(-7)) if entries.len() == 5 && integer(-1) == Some(1) => {
            verify_es256(&entries, &browser)?;
        }
        (Some(3), Some(-257)) if entries.len() == 4 => verify_rs256(&entries, &browser)?,
        _ => return Err(PaKeyError::UserVerification),
    }
    Ok(consumed)
}

fn verify_es256(entries: &[(Value, Value)], browser: &[u8]) -> Result<()> {
    let x = cose_value(entries, -2).and_then(Value::as_bytes);
    let y = cose_value(entries, -3).and_then(Value::as_bytes);
    let (Some(x), Some(y)) = (x, y) else {
        return Err(PaKeyError::UserVerification);
    };
    if x.len() != 32 || y.len() != 32 {
        return Err(PaKeyError::UserVerification);
    }
    let mut point = [0_u8; 65];
    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..].copy_from_slice(y);
    let key = VerifyingKey::from_sec1_bytes(&point).map_err(|_| PaKeyError::UserVerification)?;
    let spki = key
        .to_public_key_der()
        .map_err(|_| PaKeyError::UserVerification)?;
    (browser == spki.as_bytes())
        .then_some(())
        .ok_or(PaKeyError::UserVerification)
}

fn verify_rs256(entries: &[(Value, Value)], browser: &[u8]) -> Result<()> {
    let modulus = cose_value(entries, -1)
        .and_then(Value::as_bytes)
        .filter(|value| {
            value.len() >= 256
                && value.len() <= 1024
                && value.first().is_some_and(|byte| byte & 0x80 != 0)
        })
        .ok_or(PaKeyError::UserVerification)?;
    let exponent = cose_value(entries, -2)
        .and_then(Value::as_bytes)
        .filter(|value| !value.is_empty() && value.len() <= 8)
        .ok_or(PaKeyError::UserVerification)?;
    let key = crate::webauthn_rsa::parse_spki(browser)?;
    (modulus == key.modulus && exponent == key.exponent)
        .then_some(())
        .ok_or(PaKeyError::UserVerification)
}

/// Ciborium normalizes widths on encode, making exact re-encoding a small
/// verifier for definite lengths, shortest forms, and CTAP2 map ordering.
fn verify_canonical_map(entries: &[(Value, Value)], encoded: &[u8]) -> Result<()> {
    let mut entries = entries.to_vec();
    entries.sort_by_key(|(key, _)| CanonicalValue::from(key.clone()));
    let mut canonical = Vec::new();
    ciborium::into_writer(&Value::Map(entries), &mut canonical)
        .map_err(|_| PaKeyError::UserVerification)?;
    (canonical == encoded)
        .then_some(())
        .ok_or(PaKeyError::UserVerification)
}

fn verify_extensions(encoded: &[u8], key_length: usize, present: bool) -> Result<()> {
    let remaining = encoded
        .get(key_length..)
        .ok_or(PaKeyError::UserVerification)?;
    if !present {
        return remaining
            .is_empty()
            .then_some(())
            .ok_or(PaKeyError::UserVerification);
    }
    let mut cursor = Cursor::new(remaining);
    let value: Value =
        ciborium::from_reader(&mut cursor).map_err(|_| PaKeyError::UserVerification)?;
    let Value::Map(entries) = value else {
        return Err(PaKeyError::UserVerification);
    };
    let consumed = usize::try_from(cursor.position()).map_err(|_| PaKeyError::UserVerification)?;
    let mut names = HashSet::new();
    (consumed == remaining.len()
        && entries
            .iter()
            .all(|(key, _)| key.as_text().is_some_and(|name| names.insert(name))))
    .then_some(())
    .ok_or(PaKeyError::UserVerification)
}

fn cose_value(entries: &[(Value, Value)], label: i128) -> Option<&Value> {
    let mut matches = entries
        .iter()
        .filter(|(key, _)| key.as_integer().map(i128::from) == Some(label));
    let value = matches.next().map(|(_, value)| value);
    (matches.next().is_none()).then_some(value).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_a_matching_canonical_rs256_cose_and_spki_pair() {
        let mut modulus = vec![0x80];
        modulus.resize(256, 0x5a);
        let exponent = vec![1, 0, 1];
        let encoded = rsa_cose(&modulus, &exponent);
        let browser = URL_SAFE_NO_PAD.encode(rsa_spki(&modulus, &exponent));
        assert_eq!(
            verify_cose_public_key(&encoded, &browser).expect("matching RS256 key"),
            encoded.len()
        );

        let changed = rsa_cose(&modulus, &[3]);
        assert!(verify_cose_public_key(&changed, &browser).is_err());
    }

    fn rsa_cose(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let mut entries = vec![
            (Value::from(1_i64), Value::from(3_i64)),
            (Value::from(3_i64), Value::from(-257_i64)),
            (Value::from(-1_i64), Value::Bytes(modulus.to_vec())),
            (Value::from(-2_i64), Value::Bytes(exponent.to_vec())),
        ];
        entries.sort_by_key(|(key, _)| CanonicalValue::from(key.clone()));
        let mut encoded = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut encoded).expect("canonical COSE");
        encoded
    }

    fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
        let mut positive_modulus = vec![0];
        positive_modulus.extend_from_slice(modulus);
        let mut key = der(0x02, &positive_modulus);
        key.extend_from_slice(&der(0x02, exponent));
        let mut bit_string = vec![0];
        bit_string.extend_from_slice(&der(0x30, &key));
        let mut body = crate::webauthn_rsa::RSA_ALGORITHM_IDENTIFIER.to_vec();
        body.extend_from_slice(&der(0x03, &bit_string));
        der(0x30, &body)
    }

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut value = vec![tag];
        if body.len() < 128 {
            value.push(u8::try_from(body.len()).expect("short length"));
        } else {
            let length = u16::try_from(body.len()).expect("bounded length");
            value.push(0x82);
            value.extend_from_slice(&length.to_be_bytes());
        }
        value.extend_from_slice(body);
        value
    }
}
