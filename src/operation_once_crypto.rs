use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

use crate::{PaKeyError, Result};

pub(crate) fn verify_signature(
    public_key_hex: &str,
    signature_hex: &str,
    payload: &[u8],
) -> Result<()> {
    let key: [u8; 32] = decode_lower_hex(public_key_hex, 32)?
        .try_into()
        .map_err(|_| PaKeyError::Authorization)?;
    let signature: [u8; 64] = decode_lower_hex(signature_hex, 64)?
        .try_into()
        .map_err(|_| PaKeyError::Authorization)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| PaKeyError::Authorization)?;
    if key.is_weak()
        || key
            .verify_strict(payload, &Signature::from_bytes(&signature))
            .is_err()
    {
        return Err(PaKeyError::Authorization);
    }
    Ok(())
}

pub(crate) fn canonical_without_signature(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value).map_err(|_| PaKeyError::Authorization)?;
    value
        .as_object_mut()
        .ok_or(PaKeyError::Authorization)?
        .remove("signature");
    let mut output = Vec::from(domain);
    write_jcs(&value, &mut output)?;
    Ok(output)
}

pub(crate) fn canonical(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(|_| PaKeyError::Authorization)?;
    let mut output = Vec::from(domain);
    write_jcs(&value, &mut output)?;
    Ok(output)
}

pub(crate) fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    canonical(&[], value)
}

fn write_jcs(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| PaKeyError::Authorization)?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_jcs(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|_| PaKeyError::Authorization)?
                        .as_bytes(),
                );
                output.push(b':');
                write_jcs(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn decode_lower_hex(value: &str, bytes: usize) -> Result<Vec<u8>> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(PaKeyError::Authorization);
    }
    hex::decode(value).map_err(|_| PaKeyError::Authorization)
}
