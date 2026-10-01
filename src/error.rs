use thiserror::Error;

pub type Result<T> = std::result::Result<T, PaKeyError>;

/// Bounded diagnostics for the one-use proof that activates a new Passkey.
///
/// These categories deliberately reveal no credential material and are not
/// used by normal authentication, where they could become a verification
/// oracle.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeyRegistrationProofRejection {
    #[error("staged candidate binding")]
    Candidate,
    #[error("challenge binding or validity")]
    Challenge,
    #[error("staged candidate context")]
    Context,
    #[error("relying-party binding")]
    RpId,
    #[error("origin binding")]
    Origin,
    #[error("credential identifier binding")]
    CredentialId,
    #[error("client data")]
    ClientData,
    #[error("authenticator data encoding")]
    AuthenticatorEncoding,
    #[error("authenticator data length")]
    AuthenticatorLength,
    #[error("authenticator user presence")]
    UserPresence,
    #[error("authenticator user verification")]
    UserVerification,
    #[error("authenticator backup flags")]
    BackupFlags,
    #[error("assertion signature")]
    Signature,
    #[error("signature counter")]
    Counter,
}

impl PasskeyRegistrationProofRejection {
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Candidate => "pa-passkey-proof-candidate-rejected",
            Self::Challenge => "pa-passkey-proof-challenge-rejected",
            Self::Context => "pa-passkey-proof-context-rejected",
            Self::RpId => "pa-passkey-proof-rp-id-rejected",
            Self::Origin => "pa-passkey-proof-origin-rejected",
            Self::CredentialId => "pa-passkey-proof-credential-id-rejected",
            Self::ClientData => "pa-passkey-proof-client-data-rejected",
            Self::AuthenticatorEncoding => "pa-passkey-proof-authenticator-encoding-rejected",
            Self::AuthenticatorLength => "pa-passkey-proof-authenticator-length-rejected",
            Self::UserPresence => "pa-passkey-proof-user-presence-rejected",
            Self::UserVerification => "pa-passkey-proof-user-verification-rejected",
            Self::BackupFlags => "pa-passkey-proof-backup-flags-rejected",
            Self::Signature => "pa-passkey-proof-signature-rejected",
            Self::Counter => "pa-passkey-proof-counter-rejected",
        }
    }
}

#[derive(Debug, Error)]
pub enum PaKeyError {
    #[error("command arguments are invalid")]
    Usage,
    #[error("PA key custody backend is unavailable")]
    Custody,
    #[error("PA platform custody provider is unavailable")]
    CustodyUnavailable,
    #[error("PA platform custody provider denied access")]
    CustodyDenied,
    #[error("PA key entropy is unavailable")]
    Entropy,
    #[error("PA key state is invalid or inconsistent")]
    State,
    #[error("PA key destruction confirmation does not match current state")]
    Confirmation,
    #[error("lost Passkey recovery confirmation does not match current state")]
    RecoveryConfirmation,
    #[error("PA key state path is not owner-only")]
    UnsafePath,
    #[error("PA key state encoding failed")]
    Encoding,
    #[error("WebAuthn ceremony or assertion is invalid")]
    UserVerification,
    #[error("Passkey registration possession proof rejected: {0}")]
    PasskeyRegistrationProof(PasskeyRegistrationProofRejection),
    #[error("authorization request is invalid or stale")]
    Authorization,
    #[error("Passkey bootstrap authorizer is not provisioned")]
    BootstrapUnavailable,
}
