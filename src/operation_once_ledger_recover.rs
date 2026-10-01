use crate::{PaKeyError, Result, operation_once_record::Phase};

pub(crate) fn temporary(directory: &crate::operation_once_ledger_dir::LedgerDir) -> Result<()> {
    let names = directory.names()?;
    if !names
        .iter()
        .any(|name| name == crate::operation_once_ledger_dir::TEMP_NAME)
    {
        return Ok(());
    }
    let wire = directory.read(
        crate::operation_once_ledger_dir::TEMP_NAME,
        crate::operation_once_record::MAX_RECORD_BYTES,
        0,
    )?;
    let temporary = match crate::operation_once_ledger_codec::decode(&wire) {
        Ok(value) => value,
        Err(PaKeyError::State) => {
            return directory.remove(crate::operation_once_ledger_dir::TEMP_NAME);
        }
        Err(error) => return Err(error),
    };
    let name = format!("operation-once-v2-{}.json", temporary.proof_digest_sha256);
    if !names.iter().any(|value| value == &name) {
        return crate::operation_once_ledger_io::rename_temporary(directory, &name, false);
    }
    let current = crate::operation_once_ledger_codec::decode(&directory.read(
        &name,
        crate::operation_once_record::MAX_RECORD_BYTES,
        1,
    )?)?;
    let same = current.proof_digest_sha256 == temporary.proof_digest_sha256
        && current.request_digest_sha256 == temporary.request_digest_sha256
        && current.request_id_digest_sha256 == temporary.request_id_digest_sha256
        && current.issued_at_epoch_s == temporary.issued_at_epoch_s
        && current.proof_expires_at_epoch_s == temporary.proof_expires_at_epoch_s
        && current.prepared_pin == temporary.prepared_pin;
    if !same {
        return Err(PaKeyError::State);
    }
    match (&current.phase, &temporary.phase) {
        (Phase::Prepared, Phase::Completed) => {
            crate::operation_once_ledger_io::rename_temporary(directory, &name, true)
        }
        (Phase::Prepared, Phase::Prepared) | (Phase::Completed, _) => {
            directory.remove(crate::operation_once_ledger_dir::TEMP_NAME)
        }
    }
}
