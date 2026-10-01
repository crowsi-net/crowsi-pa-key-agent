mod cli;
mod cli_authorization;
mod cli_destruction;
mod cli_destruction_parse;
mod cli_parse;
mod cli_passkey;
mod cli_passkey_parse;
mod cli_passkey_registration;
mod cli_passkey_registration_dispatch;
use crowsi_pa_key_agent::PaKeyError;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if arguments
        .first()
        .is_some_and(|value| value == "operation-authorize-once")
    {
        let result = crowsi_pa_key_agent::run_operation_authorize_once(
            &arguments,
            std::io::stdin().lock(),
            std::io::stdout().lock(),
        );
        if let Err(error) = result {
            report(&error);
        }
        return;
    }
    let result = cli_parse::parse(&arguments).and_then(cli::dispatch);
    match result {
        Ok(document) => match serde_json::to_string_pretty(&document) {
            Ok(encoded) => println!("{encoded}"),
            Err(_) => fail("pa-response-encoding-failed", 70),
        },
        Err(error) => report(&error),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: crowsi-pa-key-agent operation-authorize-once --config ABS_OWNER_0600 --config-sha256 sha256:<64lowerhex>"
    );
    eprintln!("usage: crowsi-pa-key-agent <operation> <arguments> --custody <absolute-json>");
    eprintln!(
        "       crowsi-pa-key-agent passkey-status --state <json> --credential <absolute-json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-recovery-revoke --state <json> --credential <json> --confirm-public-key <hex> --confirmation revoke-lost-passkey-registration"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-register-challenge --state <json> --challenge <json> --rp-id <id> --origin <origin>"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-register-stage --state <json> --challenge <json> --response <json> --candidate <json> --proof-challenge <json> --credential <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-register-confirm --state <json> --candidate <json> --proof-challenge <json> --assertion <json> --credential <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-rebind-challenge --state <json> --credential <json> --challenge <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-rebind --state <json> --credential <json> --challenge <json> --assertion <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-authentication-challenge --state <json> --credential <json> --challenge <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent passkey-authenticate --state <json> --credential <json> --challenge <json> --assertion <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent credential-authorization-challenge --state <json> --credential <json> --request <json> --identity-assertion <json> --identity-status <json> --identity-trust <json> --challenge <json> --origin <http://localhost:port>"
    );
    eprintln!(
        "       crowsi-pa-key-agent credential-authorize --state <json> --credential <json> --challenge <json> --assertion <json> --request <json> --identity-assertion <json> --identity-status <json> --identity-trust <json> --output <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent trust-domain-destroy-preflight --state <json> --credential <json> --intent <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent trust-domain-destroy-challenge --state <json> --credential <json> --intent <json> --challenge <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent trust-domain-destroy-finish --state <json> --credential <json> --intent <json> --challenge <json> --assertion <json>"
    );
    eprintln!(
        "       crowsi-pa-key-agent destroy-native --state <json> --credential <json> --confirm-public-key <hex>  # internal recovery only"
    );
    std::process::exit(64)
}

fn report(error: &PaKeyError) -> ! {
    match error {
        PaKeyError::Usage => usage(),
        PaKeyError::CustodyUnavailable => fail("pa-custody-provider-unavailable", 78),
        PaKeyError::CustodyDenied => fail("pa-custody-access-denied", 77),
        PaKeyError::Custody => fail("pa-custody-operation-failed", 78),
        PaKeyError::UnsafePath => fail("pa-state-path-not-owner-only", 65),
        PaKeyError::State => fail("pa-state-inconsistent", 65),
        PaKeyError::Confirmation => fail("pa-destruction-confirmation-mismatch", 65),
        PaKeyError::RecoveryConfirmation => fail("pa-passkey-recovery-confirmation-mismatch", 65),
        PaKeyError::Entropy => fail("pa-entropy-unavailable", 70),
        PaKeyError::Encoding => fail("pa-input-or-output-invalid", 65),
        PaKeyError::UserVerification => fail("pa-user-verification-rejected", 77),
        PaKeyError::PasskeyRegistrationProof(reason) => fail(reason.reason_code(), 77),
        PaKeyError::Authorization => fail("pa-authorization-request-rejected", 77),
        PaKeyError::BootstrapUnavailable => {
            fail("pa-passkey-bootstrap-authorizer-not-provisioned", 78)
        }
    }
}

fn fail(reason: &str, code: i32) -> ! {
    eprintln!("crowsi-pa-key-agent: {reason}");
    std::process::exit(code);
}
