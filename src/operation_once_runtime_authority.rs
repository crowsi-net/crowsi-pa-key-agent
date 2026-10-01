fn fresh_entry<S: CredentialStore>(
    store: &S,
    config: &VerifiedOperationConfig,
    state_wire: &[u8],
    request: &OperationAuthorizeOnceRequestV2,
    transaction: &mut crate::operation_once_ledger::Transaction,
    now: u64,
) -> Result<(
    crate::operation_once_pin::PreparedPin,
    u64,
    crowsi_credential_broker::CredentialEntry,
)> {
    let state = state(state_wire)?;
    let mapping = crate::operation_once_verify::verify(request, config, now)?;
    independent(&state, config, mapping, request)?;
    let reference = crate::initialization::reference()?;
    let metadata = store
        .metadata(&reference)
        .map_err(|_| PaKeyError::Custody)?;
    if metadata.revision().as_str() != state.credential_revision {
        return Err(PaKeyError::State);
    }
    let entry = store
        .get(&reference, &state.credential_revision)
        .map_err(|_| PaKeyError::Custody)?;
    if entry.metadata().revision().as_str() != state.credential_revision {
        return Err(PaKeyError::State);
    }
    let pin = crate::operation_once_pin::PreparedPin::new(&state, mapping)?;
    transaction.prepare(
        now,
        request.target_device_proof.expires_at_epoch_s,
        pin.clone(),
    )?;
    Ok((pin, now, entry))
}

fn pinned_entry<S: CredentialStore>(
    store: &S,
    pin: &crate::operation_once_pin::PreparedPin,
) -> Result<crowsi_credential_broker::CredentialEntry> {
    let entry = store
        .get(
            &crate::initialization::reference()?,
            &pin.pa_credential_revision,
        )
        .map_err(|_| PaKeyError::Custody)?;
    (entry.metadata().revision().as_str() == pin.pa_credential_revision)
        .then_some(entry)
        .ok_or(PaKeyError::State)
}
