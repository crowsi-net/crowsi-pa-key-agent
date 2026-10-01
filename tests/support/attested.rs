use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

pub fn assertion_auth_data(rp_id: &str, count: u32, flags: u8) -> Vec<u8> {
    let mut value = Sha256::digest(rp_id.as_bytes()).to_vec();
    value.push(flags);
    value.extend_from_slice(&count.to_be_bytes());
    value
}

pub fn registration_auth_data(rp_id: &str, signing: &SigningKey) -> Vec<u8> {
    registration_auth_data_with_count(rp_id, signing, 0)
}

pub fn registration_auth_data_with_count(rp_id: &str, signing: &SigningKey, count: u32) -> Vec<u8> {
    let mut value = assertion_auth_data(rp_id, count, 0x45);
    value.extend_from_slice(&[0_u8; 16]);
    let credential_id = b"credential-1";
    let id_length = u16::try_from(credential_id.len()).expect("credential id length");
    value.extend_from_slice(&id_length.to_be_bytes());
    value.extend_from_slice(credential_id);
    let point = signing.verifying_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    value.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01]);
    value.extend_from_slice(&[0x21, 0x58, 0x20]);
    value.extend_from_slice(&bytes[1..33]);
    value.extend_from_slice(&[0x22, 0x58, 0x20]);
    value.extend_from_slice(&bytes[33..65]);
    value
}

pub fn registration_auth_data_with_cred_protect(rp_id: &str, signing: &SigningKey) -> Vec<u8> {
    let mut value = registration_auth_data(rp_id, signing);
    value[32] |= 0x80;
    value.extend_from_slice(&[
        0xa1, 0x6b, b'c', b'r', b'e', b'd', b'P', b'r', b'o', b't', b'e', b'c', b't', 0x02,
    ]);
    value
}
