use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};
use sha2::{Digest, Sha256};

use crate::{
    PaKeyError, Result,
    webauthn_model::{ClientData, PasskeyAssertionV1, PasskeyChallengeV1, PasskeyCredentialV1},
};

pub(crate) fn verify_assertion_signature(
    credential: &PasskeyCredentialV1,
    assertion: &PasskeyAssertionV1,
    client: &[u8],
    authenticator: &[u8],
) -> Result<()> {
    let public = decode(&credential.public_key_spki_b64url)?;
    let signature = decode(&assertion.signature_b64url)?;
    let mut signed = authenticator.to_vec();
    signed.extend_from_slice(&Sha256::digest(client));
    if let Ok(key) = VerifyingKey::from_public_key_der(&public) {
        let signature =
            Signature::from_der(&signature).map_err(|_| PaKeyError::UserVerification)?;
        return key
            .verify(&signed, &signature)
            .map_err(|_| PaKeyError::UserVerification);
    }
    crate::webauthn_rsa::verify_rs256(&public, &signed, &signature)
}

pub(crate) fn verify_ceremony_data(
    client: &[u8],
    authenticator: &[u8],
    challenge: &PasskeyChallengeV1,
    kind: &str,
) -> Result<()> {
    let data: ClientData =
        serde_json::from_slice(client).map_err(|_| PaKeyError::UserVerification)?;
    let rp_hash = Sha256::digest(challenge.rp_id.as_bytes());
    let flags = authenticator.get(32).copied().unwrap_or_default();
    let valid = data.kind == kind
        && data.challenge == challenge.challenge_b64url
        && data.origin == challenge.origin
        && !data.cross_origin
        && authenticator.len() >= 37
        && authenticator[..32] == rp_hash[..]
        && flags & 0x01 != 0
        && flags & 0x04 != 0
        && !(flags & 0x10 != 0 && flags & 0x08 == 0);
    valid.then_some(()).ok_or(PaKeyError::UserVerification)
}

pub(crate) fn counter(authenticator: &[u8]) -> Result<u32> {
    let bytes: [u8; 4] = authenticator
        .get(33..37)
        .and_then(|value| value.try_into().ok())
        .ok_or(PaKeyError::UserVerification)?;
    Ok(u32::from_be_bytes(bytes))
}

pub(crate) fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PaKeyError::UserVerification)
}
