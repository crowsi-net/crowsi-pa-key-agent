use crate::{
    PaKeyError,
    cli_parse::{Command, RegistrationCommand, absolute, pairs},
};

pub fn parse(arguments: &[String]) -> Result<Option<Command>, PaKeyError> {
    let Some(operation) = arguments.first().map(String::as_str) else {
        return Ok(None);
    };
    let flags = match operation {
        "passkey-status" => &["--state", "--credential"][..],
        "passkey-recovery-revoke" => &[
            "--state",
            "--credential",
            "--confirm-public-key",
            "--confirmation",
        ],
        "passkey-register-challenge" => &["--state", "--challenge", "--rp-id", "--origin"],
        "passkey-register-stage" => &[
            "--state",
            "--challenge",
            "--response",
            "--candidate",
            "--proof-challenge",
            "--credential",
        ],
        "passkey-register-confirm" => &[
            "--state",
            "--candidate",
            "--proof-challenge",
            "--assertion",
            "--credential",
        ],
        "passkey-rebind-challenge" | "passkey-authentication-challenge" => {
            &["--state", "--credential", "--challenge"]
        }
        "passkey-rebind" | "passkey-authenticate" => {
            &["--state", "--credential", "--challenge", "--assertion"]
        }
        "credential-authorization-challenge" => &[
            "--state",
            "--credential",
            "--request",
            "--identity-assertion",
            "--identity-status",
            "--identity-trust",
            "--challenge",
            "--origin",
        ],
        "credential-authorize" => &[
            "--state",
            "--credential",
            "--challenge",
            "--assertion",
            "--request",
            "--identity-assertion",
            "--identity-status",
            "--identity-trust",
            "--output",
        ],
        _ => return Ok(None),
    };
    Ok(Some(build(operation, &pairs(arguments, flags)?)?))
}

fn build(operation: &str, values: &[String]) -> Result<Command, PaKeyError> {
    Ok(match operation {
        "passkey-status" => Command::PasskeyStatus {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
        },
        "passkey-recovery-revoke" => Command::PasskeyRecoveryRevoke {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            expected_public_key: values[2].clone(),
            confirmation: values[3].clone(),
        },
        "passkey-register-challenge" => Command::Registration(RegistrationCommand::Challenge {
            state: absolute(&values[0])?,
            challenge: absolute(&values[1])?,
            rp_id: values[2].clone(),
            origin: values[3].clone(),
        }),
        "passkey-register-stage" => Command::Registration(RegistrationCommand::Stage {
            state: absolute(&values[0])?,
            challenge: absolute(&values[1])?,
            response: absolute(&values[2])?,
            candidate: absolute(&values[3])?,
            proof_challenge: absolute(&values[4])?,
            credential: absolute(&values[5])?,
        }),
        "passkey-register-confirm" => Command::Registration(RegistrationCommand::Confirm {
            state: absolute(&values[0])?,
            candidate: absolute(&values[1])?,
            proof_challenge: absolute(&values[2])?,
            assertion: absolute(&values[3])?,
            credential: absolute(&values[4])?,
        }),
        "passkey-rebind-challenge" => Command::RebindChallenge {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            challenge: absolute(&values[2])?,
        },
        "passkey-rebind" => Command::Rebind {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            challenge: absolute(&values[2])?,
            assertion: absolute(&values[3])?,
        },
        "passkey-authentication-challenge" => Command::PasskeyAuthenticationChallenge {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            challenge: absolute(&values[2])?,
        },
        "passkey-authenticate" => Command::PasskeyAuthenticate {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            challenge: absolute(&values[2])?,
            assertion: absolute(&values[3])?,
        },
        "credential-authorization-challenge" => Command::AuthorizationChallenge {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            request: absolute(&values[2])?,
            identity_assertion: absolute(&values[3])?,
            identity_status: absolute(&values[4])?,
            identity_trust: absolute(&values[5])?,
            challenge: absolute(&values[6])?,
            origin: values[7].clone(),
        },
        "credential-authorize" => Command::Authorize {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            challenge: absolute(&values[2])?,
            assertion: absolute(&values[3])?,
            request: absolute(&values[4])?,
            identity_assertion: absolute(&values[5])?,
            identity_status: absolute(&values[6])?,
            identity_trust: absolute(&values[7])?,
            output: absolute(&values[8])?,
        },
        _ => return Err(PaKeyError::Usage),
    })
}

#[cfg(test)]
#[path = "cli_authorization_parse_tests.rs"]
mod authorization_tests;
#[cfg(test)]
#[path = "cli_passkey_parse_tests.rs"]
mod tests;
