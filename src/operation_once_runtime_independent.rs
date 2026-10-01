fn independent(
    state: &PaKeyStateV1,
    config: &VerifiedOperationConfig,
    mapping: &crate::operation_once_config::OperationCredentialMappingV1,
    request: &OperationAuthorizeOnceRequestV2,
) -> Result<()> {
    let keys = [
        &config.0.identity_public_key_hex,
        &config.0.current_status_public_key_hex,
        &config.0.fresh_uv_public_key_hex,
        &config.0.authority_response_public_key_hex,
        &config.1,
    ];
    let sender = session_sender_key_id(request).ok_or(PaKeyError::Authorization)?;
    let role_ids = [
        &config.0.identity_key_id,
        &config.0.current_status_key_id,
        &config.0.fresh_uv_key_id,
        &config.0.authority_response_key_id,
        &config.0.configuration_key_id,
    ];
    (state.key_id != mapping.custody_credential_id
        && state.key_id != sender
        && mapping.custody_credential_id != sender
        && !role_ids.contains(&&mapping.custody_credential_id)
        && !keys.contains(&&state.public_key_hex))
    .then_some(())
    .ok_or(PaKeyError::Authorization)
}

fn session_sender_key_id(request: &OperationAuthorizeOnceRequestV2) -> Option<&str> {
    use ihat_identity_assertion_contracts::AuthorityEvidence;

    let [AuthorityEvidence::Signed(selected)] = request
        .selected_identity_exchange
        .request
        .evidence
        .as_slice()
    else {
        return None;
    };
    let [AuthorityEvidence::Signed(current)] = request
        .current_identity_exchange
        .request
        .evidence
        .as_slice()
    else {
        return None;
    };
    (selected.key_id == current.key_id).then_some(current.key_id.as_str())
}
