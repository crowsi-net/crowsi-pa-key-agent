use std::path::Path;

#[derive(Clone, Copy)]
pub struct CredentialAuthorizationFiles<'a> {
    pub state: &'a Path,
    pub credential: &'a Path,
    pub request: &'a Path,
    pub identity_assertion: &'a Path,
    pub identity_status: &'a Path,
    pub identity_trust: &'a Path,
}

impl<'a> CredentialAuthorizationFiles<'a> {
    #[must_use]
    pub const fn new(
        state: &'a Path,
        credential: &'a Path,
        request: &'a Path,
        identity_assertion: &'a Path,
        identity_status: &'a Path,
        identity_trust: &'a Path,
    ) -> Self {
        Self {
            state,
            credential,
            request,
            identity_assertion,
            identity_status,
            identity_trust,
        }
    }
}
