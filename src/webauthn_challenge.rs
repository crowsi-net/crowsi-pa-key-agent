use std::path::Path;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::{PaKeyError, Result, private_json, webauthn_model::PasskeyChallengeV1};

const CHALLENGE_TTL_SECONDS: i64 = 180;

/// Creates a short-lived, loopback-bound `WebAuthn` challenge.
///
/// # Errors
///
/// Rejects unsupported origins, invalid bindings, unsafe output paths, or an
/// unavailable operating-system random source.
#[cfg(feature = "bootstrap-authorizer-internal")]
pub fn create_challenge(
    output: &Path,
    operation: &str,
    rp_id: &str,
    origin: &str,
    binding_sha256: &str,
) -> Result<PasskeyChallengeV1> {
    if !matches!(
        operation,
        "register" | "credential-enroll" | "github-provider-observe"
    ) {
        return Err(PaKeyError::UserVerification);
    }
    create_bound_challenge(output, operation, rp_id, origin, binding_sha256)
}

pub(crate) fn create_bound_challenge(
    output: &Path,
    operation: &str,
    rp_id: &str,
    origin: &str,
    binding_sha256: &str,
) -> Result<PasskeyChallengeV1> {
    create_context_bound_challenge(output, operation, rp_id, origin, binding_sha256, None)
}

pub(crate) fn create_context_bound_challenge(
    output: &Path,
    operation: &str,
    rp_id: &str,
    origin: &str,
    binding_sha256: &str,
    context_sha256: Option<&str>,
) -> Result<PasskeyChallengeV1> {
    if !matches!(
        operation,
        "register"
            | "credential-enroll"
            | "github-provider-observe"
            | "passkey-registration-proof"
            | "passkey-rebind"
            | "passkey-authentication"
            | "trust-domain-destroy"
    ) || !valid_local_origin(rp_id, origin)
        || !valid_digest(binding_sha256)
        || context_sha256.is_some_and(|value| !valid_digest(value))
    {
        return Err(PaKeyError::UserVerification);
    }
    let mut challenge = [0_u8; 32];
    let mut ceremony = [0_u8; 16];
    getrandom::fill(&mut challenge).map_err(|_| PaKeyError::Entropy)?;
    getrandom::fill(&mut ceremony).map_err(|_| PaKeyError::Entropy)?;
    let value = PasskeyChallengeV1 {
        schema: "crowsi://policy-authority/passkey-challenge/v1".into(),
        ceremony_id: format!("ceremony-{}", hex::encode(ceremony)),
        operation: operation.into(),
        challenge_b64url: URL_SAFE_NO_PAD.encode(challenge),
        rp_id: rp_id.into(),
        origin: origin.into(),
        binding_sha256: binding_sha256.into(),
        context_sha256: context_sha256.map(str::to_owned),
        expires_at_epoch_s: now()
            .checked_add(CHALLENGE_TTL_SECONDS)
            .ok_or(PaKeyError::State)?,
    };
    private_json::write_new(output, &value)?;
    Ok(value)
}

pub(crate) fn valid_challenge(value: &PasskeyChallengeV1, operation: &str) -> bool {
    value.schema == "crowsi://policy-authority/passkey-challenge/v1"
        && value.operation == operation
        && value.expires_at_epoch_s >= now()
        && value.expires_at_epoch_s <= now().saturating_add(CHALLENGE_TTL_SECONDS)
        && valid_local_origin(&value.rp_id, &value.origin)
        && valid_digest(&value.binding_sha256)
        && value.context_sha256.as_deref().is_none_or(valid_digest)
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| i64::try_from(value.as_secs()).ok())
        .unwrap_or(0)
}

pub(crate) fn valid_local_origin(rp_id: &str, origin: &str) -> bool {
    if rp_id != "localhost" {
        return false;
    }
    let Some(port_text) = origin.strip_prefix("http://localhost:") else {
        return false;
    };
    port_text
        .parse::<u16>()
        .is_ok_and(|port| port > 0 && port_text == port.to_string())
}

pub(crate) fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::valid_local_origin;

    #[test]
    fn local_origin_requires_a_canonical_explicit_port() {
        for origin in ["http://localhost:1", "http://localhost:65535"] {
            assert!(valid_local_origin("localhost", origin));
        }
        for origin in [
            "http://localhost",
            "http://localhost:0",
            "http://localhost:04203",
            "http://localhost:65536",
            "http://localhost:@evil.test",
            "http://localhost:4203/path",
            "https://localhost",
        ] {
            assert!(
                !valid_local_origin("localhost", origin),
                "accepted {origin}"
            );
        }
        assert!(!valid_local_origin("127.0.0.1", "http://127.0.0.1:4203"));
    }
}
