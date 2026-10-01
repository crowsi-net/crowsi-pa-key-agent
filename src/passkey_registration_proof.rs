use sha2::{Digest, Sha256};

use crate::{
    PasskeyChallengeV1, PasskeyCredentialV1, PasskeyRegistrationProofRejection as Rejection,
    webauthn_assertion::{counter, decode, verify_assertion_signature},
    webauthn_challenge::valid_challenge,
    webauthn_model::{ClientData, PasskeyAssertionV1, PasskeyRegistrationCandidateV1},
};

pub(crate) fn verify_state(
    candidate: &PasskeyRegistrationCandidateV1,
    target: &str,
    proof: &PasskeyChallengeV1,
    assertion: &PasskeyAssertionV1,
    expected_binding: &str,
    expected_context: &str,
) -> Result<(), Rejection> {
    let credential = &candidate.credential;
    if candidate.schema != "crowsi://policy-authority/passkey-registration-candidate/v1"
        || candidate.target_sha256 != target
        || credential.pa_public_key_sha256 != expected_binding
    {
        return Err(Rejection::Candidate);
    }
    if proof.rp_id != credential.rp_id {
        return Err(Rejection::RpId);
    }
    if proof.origin != credential.origin {
        return Err(Rejection::Origin);
    }
    if proof.context_sha256.as_deref() != Some(expected_context) {
        return Err(Rejection::Context);
    }
    if !valid_challenge(proof, "passkey-registration-proof")
        || proof.binding_sha256 != expected_binding
    {
        return Err(Rejection::Challenge);
    }
    if assertion.credential_id_b64url != credential.credential_id_b64url {
        return Err(Rejection::CredentialId);
    }
    Ok(())
}

pub(crate) fn verify_evidence(
    credential: &PasskeyCredentialV1,
    proof: &PasskeyChallengeV1,
    assertion: &PasskeyAssertionV1,
) -> Result<u32, Rejection> {
    let client = decode(&assertion.client_data_json_b64url).map_err(|_| Rejection::ClientData)?;
    let authenticator = decode(&assertion.authenticator_data_b64url)
        .map_err(|_| Rejection::AuthenticatorEncoding)?;
    let data: ClientData = serde_json::from_slice(&client).map_err(|_| Rejection::ClientData)?;
    if data.kind != "webauthn.get" || data.cross_origin {
        return Err(Rejection::ClientData);
    }
    if data.challenge != proof.challenge_b64url {
        return Err(Rejection::Challenge);
    }
    if data.origin != proof.origin {
        return Err(Rejection::Origin);
    }
    if authenticator.len() < 37 {
        return Err(Rejection::AuthenticatorLength);
    }
    if authenticator[..32] != Sha256::digest(proof.rp_id.as_bytes())[..] {
        return Err(Rejection::RpId);
    }
    verify_assertion_signature(credential, assertion, &client, &authenticator)
        .map_err(|_| Rejection::Signature)?;
    let flags = authenticator[32];
    if flags & 0x01 == 0 {
        return Err(Rejection::UserPresence);
    }
    if flags & 0x04 == 0 {
        return Err(Rejection::UserVerification);
    }
    if flags & 0x10 != 0 && flags & 0x08 == 0 {
        return Err(Rejection::BackupFlags);
    }
    counter(&authenticator).map_err(|_| Rejection::Counter)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use p256::{ecdsa::SigningKey, pkcs8::EncodePublicKey};

    use super::*;

    #[test]
    fn accepts_the_w3c_es256_high_s_assertion_vector() {
        let private = bytes("6fd2149bb5f1597fe549b138794bde61893b2dc32ca316de65f04808dac211dc");
        let signing = SigningKey::from_bytes(private.as_slice().into()).expect("private key");
        let public = signing.verifying_key().to_public_key_der().expect("SPKI");
        let challenge = "7x3rpW3OSPZ0pEfM9juVmSWM6HZI5cOW8u8ModpGDjs";
        let proof = PasskeyChallengeV1 {
            schema: String::new(),
            ceremony_id: String::new(),
            operation: String::new(),
            challenge_b64url: challenge.into(),
            rp_id: "example.org".into(),
            origin: "https://example.org".into(),
            binding_sha256: String::new(),
            context_sha256: None,
            expires_at_epoch_s: 0,
        };
        let credential = PasskeyCredentialV1 {
            schema: String::new(),
            credential_id_b64url: "AQ".into(),
            public_key_spki_b64url: URL_SAFE_NO_PAD.encode(public.as_bytes()),
            rp_id: proof.rp_id.clone(),
            origin: proof.origin.clone(),
            pa_public_key_sha256: String::new(),
            sign_count: 0,
            registered_at_epoch_s: 0,
        };
        let assertion = PasskeyAssertionV1 {
            credential_id_b64url: credential.credential_id_b64url.clone(),
            authenticator_data_b64url: encoded(
                "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000",
            ),
            client_data_json_b64url: encoded(
                "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22377833727057334f53505a307045664d396a75566d53574d36485a4935634f573875384d6f647047446a73222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
            ),
            signature_b64url: encoded(
                "304502203ecef83fb12a0cae7841055f9f87103a99fd14b424194bbf06c4623d3ee6e3fd022100d2ace346db262b1374a6b70faa51f518a42ddca13a4125ce6f5052a75bac9fb6",
            ),
        };

        assert_eq!(verify_evidence(&credential, &proof, &assertion), Ok(0));
    }

    fn encoded(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(bytes(value))
    }

    fn bytes(value: &str) -> Vec<u8> {
        hex::decode(value).expect("hex")
    }
}
