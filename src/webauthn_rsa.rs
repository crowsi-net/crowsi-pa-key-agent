use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};

use crate::{PaKeyError, Result};

pub(crate) const RSA_ALGORITHM_IDENTIFIER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

pub(crate) struct RsaPublicParts<'a> {
    pub modulus: &'a [u8],
    pub exponent: &'a [u8],
}

pub(crate) fn verify_rs256(spki: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = parse_spki(spki)?;
    RsaPublicKeyComponents {
        n: key.modulus,
        e: key.exponent,
    }
    .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
    .map_err(|_| PaKeyError::UserVerification)
}

pub(crate) fn parse_spki(value: &[u8]) -> Result<RsaPublicParts<'_>> {
    let outer = exact_tlv(value, 0x30)?;
    let mut position = 0;
    let algorithm = read_tlv(outer, &mut position, 0x30)?;
    if encoded_tlv(0x30, algorithm)? != RSA_ALGORITHM_IDENTIFIER {
        return Err(PaKeyError::UserVerification);
    }
    let bit_string = read_tlv(outer, &mut position, 0x03)?;
    if position != outer.len() || bit_string.first() != Some(&0) {
        return Err(PaKeyError::UserVerification);
    }
    let key = exact_tlv(&bit_string[1..], 0x30)?;
    let mut key_position = 0;
    let modulus = positive_integer(read_tlv(key, &mut key_position, 0x02)?)?;
    let exponent = positive_integer(read_tlv(key, &mut key_position, 0x02)?)?;
    if key_position != key.len()
        || !(256..=1024).contains(&modulus.len())
        || modulus.first().is_none_or(|value| value & 0x80 == 0)
        || exponent.is_empty()
        || exponent.len() > 8
        || !valid_exponent(exponent)
    {
        return Err(PaKeyError::UserVerification);
    }
    Ok(RsaPublicParts { modulus, exponent })
}

fn valid_exponent(value: &[u8]) -> bool {
    let exponent = value
        .iter()
        .fold(0_u64, |result, byte| (result << 8) | u64::from(*byte));
    exponent >= 3 && exponent & 1 == 1
}

fn exact_tlv(value: &[u8], tag: u8) -> Result<&[u8]> {
    let mut position = 0;
    let body = read_tlv(value, &mut position, tag)?;
    (position == value.len())
        .then_some(body)
        .ok_or(PaKeyError::UserVerification)
}

fn read_tlv<'a>(value: &'a [u8], position: &mut usize, tag: u8) -> Result<&'a [u8]> {
    if value.get(*position) != Some(&tag) {
        return Err(PaKeyError::UserVerification);
    }
    *position += 1;
    let first = *value.get(*position).ok_or(PaKeyError::UserVerification)?;
    *position += 1;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 2 || value.get(*position) == Some(&0) {
            return Err(PaKeyError::UserVerification);
        }
        let mut result = 0_usize;
        for byte in value
            .get(*position..*position + count)
            .ok_or(PaKeyError::UserVerification)?
        {
            result = result
                .checked_mul(256)
                .and_then(|current| current.checked_add(usize::from(*byte)))
                .ok_or(PaKeyError::UserVerification)?;
        }
        *position += count;
        if result < 128 {
            return Err(PaKeyError::UserVerification);
        }
        result
    };
    let end = position
        .checked_add(length)
        .filter(|end| *end <= value.len())
        .ok_or(PaKeyError::UserVerification)?;
    let result = &value[*position..end];
    *position = end;
    Ok(result)
}

fn positive_integer(value: &[u8]) -> Result<&[u8]> {
    let result = match value {
        [0, next, rest @ ..] if next & 0x80 != 0 => {
            let _ = rest;
            &value[1..]
        }
        [first, ..] if first & 0x80 == 0 => value,
        _ => return Err(PaKeyError::UserVerification),
    };
    (!result.is_empty())
        .then_some(result)
        .ok_or(PaKeyError::UserVerification)
}

fn encoded_tlv(tag: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut value = vec![tag];
    if body.len() < 128 {
        value.push(u8::try_from(body.len()).map_err(|_| PaKeyError::UserVerification)?);
    } else if body.len() <= 255 {
        value.extend_from_slice(&[
            0x81,
            u8::try_from(body.len()).map_err(|_| PaKeyError::UserVerification)?,
        ]);
    } else {
        let length = u16::try_from(body.len()).map_err(|_| PaKeyError::UserVerification)?;
        value.push(0x82);
        value.extend_from_slice(&length.to_be_bytes());
    }
    value.extend_from_slice(body);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_canonical_or_non_rsa_spki() {
        assert!(parse_spki(&[]).is_err());
        assert!(parse_spki(&[0x30, 0x81, 0]).is_err());
        assert!(parse_spki(&[0x30, 0]).is_err());
    }

    #[test]
    fn parses_one_canonical_2048_bit_rsa_spki() {
        let mut modulus = vec![0x80];
        modulus.resize(256, 0x5a);
        let mut positive_modulus = vec![0];
        positive_modulus.extend_from_slice(&modulus);
        let mut pkcs1 = encoded_tlv(0x02, &positive_modulus).expect("modulus");
        pkcs1.extend_from_slice(&encoded_tlv(0x02, &[1, 0, 1]).expect("exponent"));
        let pkcs1 = encoded_tlv(0x30, &pkcs1).expect("key");
        let mut bit_string = vec![0];
        bit_string.extend_from_slice(&pkcs1);
        let mut body = RSA_ALGORITHM_IDENTIFIER.to_vec();
        body.extend_from_slice(&encoded_tlv(0x03, &bit_string).expect("bit string"));
        let spki = encoded_tlv(0x30, &body).expect("SPKI");

        let parsed = parse_spki(&spki).expect("canonical RSA SPKI");
        assert_eq!(parsed.modulus, modulus);
        assert_eq!(parsed.exponent, [1, 0, 1]);
        assert!(verify_rs256(&spki, b"message", &[0; 256]).is_err());
    }
}
