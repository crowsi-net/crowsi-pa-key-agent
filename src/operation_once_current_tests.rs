use ihat_identity_assertion_contracts::{AuthorityCommand, AuthorityEvidence};

use crate::{operation_once_test_support::Fixture, operation_once_verify};

#[test]
fn pa_06_rejects_authority_response_signature_key_or_generation_substitution() {
    let mut signature = Fixture::new();
    signature
        .request
        .current_identity_exchange
        .response
        .signature = "00".repeat(64);
    assert!(verify(&signature).is_err());

    let mut key = Fixture::new();
    key.config.0.authority_response_public_key_hex = key.config.0.identity_public_key_hex.clone();
    assert!(verify(&key).is_err());

    let mut generation = Fixture::new();
    generation.config.0.minimum_identity_config_generation = 9;
    assert!(verify(&generation).is_err());
}

#[test]
fn pa_06_rejects_current_session_epoch_and_posture_drift_after_finish() {
    for case in 0..3 {
        let mut fixture = Fixture::new();
        let identity = fixture.current_mut();
        match case {
            0 => {
                identity.assertion.session_ref = "session-other".into();
                identity.current_status.session_ref = "session-other".into();
            }
            1 => {
                identity.assertion.revocation_epochs.session += 1;
                identity.current_status.revocation_epochs.session += 1;
            }
            _ => {
                identity.assertion.device_posture.revision += 1;
                identity.current_status.device_posture.revision += 1;
            }
        }
        fixture.resign_current();
        assert!(verify(&fixture).is_err());
    }
}

#[test]
fn pa_06_rejects_selected_identity_reuse_and_session_sender_device_key_alias() {
    let mut stale = Fixture::new();
    stale.request.current_identity_exchange = stale.request.selected_identity_exchange.clone();
    stale.request.target_device_proof.status_nonce = stale.current().current_status.nonce.clone();
    stale.rebind_sign_digest();
    assert!(verify(&stale).is_err());

    let mut alias = Fixture::new();
    for exchange in [
        &mut alias.request.selected_identity_exchange,
        &mut alias.request.current_identity_exchange,
    ] {
        let [AuthorityEvidence::Signed(sender)] = exchange.request.evidence.as_mut_slice() else {
            unreachable!()
        };
        sender.key_id = "proof-key-b".into();
    }
    assert!(verify(&alias).is_err());
}

#[test]
fn pa_06_rejects_session_sender_fingerprint_drift_after_selection() {
    let mut fixture = Fixture::new();
    let AuthorityCommand::IssueCurrentDeviceIdentityEvidence(command) =
        &mut fixture.request.current_identity_exchange.request.command
    else {
        unreachable!()
    };
    command.session_sender_key_fingerprint = "66".repeat(32);
    fixture.resign_current();
    assert!(verify(&fixture).is_err());
}

fn verify(
    fixture: &Fixture,
) -> crate::Result<&crate::operation_once_config::OperationCredentialMappingV1> {
    operation_once_verify::verify(&fixture.request, &fixture.config, fixture.now)
}
