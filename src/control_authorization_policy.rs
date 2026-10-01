use crowsi_local_control_bridge::{BridgeAction, ControlRequestV1};

use crate::{PaKeyError, Result};

pub(crate) struct ControlAuthorizationPolicy {
    pub(crate) operation: &'static str,
    pub(crate) workload_id: &'static str,
    pub(crate) actor_profile_id: &'static str,
}

/// Narrows PA issuance to reviewed local-control operations.
pub(crate) fn require(request: &ControlRequestV1) -> Result<ControlAuthorizationPolicy> {
    let policy = match request.action {
        BridgeAction::EnrollCredential if credential_enrollment(request) => {
            ControlAuthorizationPolicy {
                operation: "credential-enroll",
                workload_id: "spiffe://crowsi/local/credential-agent",
                actor_profile_id: "profile-credential-operator",
            }
        }
        BridgeAction::ObserveProvider if github_observation(request) => {
            ControlAuthorizationPolicy {
                operation: "github-provider-observe",
                workload_id: "spiffe://crowsi/local/coela-github-app",
                actor_profile_id: "profile-github-observer-operator",
            }
        }
        _ => return Err(PaKeyError::Authorization),
    };
    if request.schema != "crowsi://local-control/request/v1"
        || !identifier(&request.request_id)
        || !digest(&request.body_sha256)
    {
        return Err(PaKeyError::Authorization);
    }
    Ok(policy)
}

fn credential_enrollment(value: &ControlRequestV1) -> bool {
    value.purpose == "credential-enrollment"
        && value.resource.len() == 75
        && value.resource.starts_with("credential-")
        && value.resource[11..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn github_observation(value: &ControlRequestV1) -> bool {
    const PREFIX: &str = "crowsi://credentials/github-app/";
    value.purpose == "github-app-jwt-signing"
        && value
            .resource
            .strip_prefix(PREFIX)
            .is_some_and(|credential| {
                !credential.is_empty() && credential.len() <= 128 && component(credential)
            })
}

fn component(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b":._/-".contains(&byte))
}

fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
