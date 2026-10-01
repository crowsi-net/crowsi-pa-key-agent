use crate::{PaKeyError, Result, operation_once_digest::Binding, operation_once_record::Record};

pub(crate) const MAX_ENTRIES: usize = 128;
pub(crate) const MAX_TOTAL_BYTES: u64 =
    MAX_ENTRIES as u64 * crate::operation_once_record::MAX_RECORD_BYTES;

pub(crate) struct Snapshot {
    pub exact: Option<Record>,
    pub entries: usize,
    pub bytes: u64,
}

pub(crate) fn scan(
    directory: &crate::operation_once_ledger_dir::LedgerDir,
    binding: &Binding,
    now: u64,
) -> Result<Snapshot> {
    crate::operation_once_ledger_recover::temporary(directory)?;
    crate::operation_once_ledger_watermark::advance(directory, now)?;
    let mut exact = None;
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    for name in directory.names()? {
        if name == crate::operation_once_ledger_dir::LOCK_NAME
            || name == crate::operation_once_ledger_dir::WATERMARK_NAME
        {
            continue;
        }
        if name == crate::operation_once_ledger_dir::TEMP_NAME {
            return Err(PaKeyError::State);
        }
        let wire = directory.read(&name, crate::operation_once_record::MAX_RECORD_BYTES, 1)?;
        if crate::operation_once_legacy::valid_name(&name) {
            let legacy = crate::operation_once_legacy::LegacyReceipt::decode(&name, &wire)?;
            if now >= legacy.retain_until()? {
                directory.remove(&name)?;
                continue;
            }
            if name == crate::operation_once_legacy::file_name(binding)? {
                return Err(PaKeyError::Authorization);
            }
        } else {
            let record = current(&name, &wire)?;
            if now >= record.retain_until_epoch_s {
                directory.remove(&name)?;
                continue;
            }
            collision(&record, binding, &mut exact)?;
        }
        entries = entries.checked_add(1).ok_or(PaKeyError::State)?;
        bytes = bytes
            .checked_add(u64::try_from(wire.len()).map_err(|_| PaKeyError::State)?)
            .ok_or(PaKeyError::State)?;
    }
    if entries > MAX_ENTRIES || bytes > MAX_TOTAL_BYTES {
        return Err(PaKeyError::State);
    }
    Ok(Snapshot {
        exact,
        entries,
        bytes,
    })
}

fn current(name: &str, wire: &[u8]) -> Result<Record> {
    if !valid_name(name) {
        return Err(PaKeyError::State);
    }
    let record = crate::operation_once_ledger_codec::decode(wire)?;
    (name == format!("operation-once-v2-{}.json", record.proof_digest_sha256))
        .then_some(record)
        .ok_or(PaKeyError::State)
}

fn collision(record: &Record, binding: &Binding, exact: &mut Option<Record>) -> Result<()> {
    if record.proof_digest_sha256 == binding.proof {
        if !record.binding_matches(binding) || exact.is_some() {
            return Err(PaKeyError::Authorization);
        }
        *exact = Some(record.clone());
    } else if record.request_id_digest_sha256 == binding.request_id {
        return Err(PaKeyError::Authorization);
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    let Some(digest) = value
        .strip_prefix("operation-once-v2-")
        .and_then(|name| name.strip_suffix(".json"))
    else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
