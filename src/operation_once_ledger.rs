use std::path::Path;

use crowsi_windows_operation_contracts::OperationAuthorizeOnceRequestV2;

use crate::{PaKeyError, Result, operation_once_digest::Binding, operation_once_record::Record};

pub(crate) struct Transaction {
    locked: crate::operation_once_ledger_lock::LockedLedger,
    binding: Binding,
    record: Option<Record>,
    entries: usize,
    bytes: u64,
}

impl Transaction {
    pub(crate) fn open(
        directory: &Path,
        request: &OperationAuthorizeOnceRequestV2,
        now: u64,
    ) -> Result<Self> {
        let binding = Binding::new(request)?;
        let locked = crate::operation_once_ledger_lock::LockedLedger::acquire(directory)?;
        let snapshot = crate::operation_once_ledger_scan::scan(&locked.directory, &binding, now)?;
        Ok(Self {
            locked,
            binding,
            record: snapshot.exact,
            entries: snapshot.entries,
            bytes: snapshot.bytes,
        })
    }

    pub(crate) fn response(&self) -> Result<Option<Vec<u8>>> {
        self.record.as_ref().map_or(Ok(None), Record::response)
    }

    pub(crate) fn issued_at(&self) -> Option<u64> {
        self.record.as_ref().map(|value| value.issued_at_epoch_s)
    }

    pub(crate) fn prepare(
        &mut self,
        issued: u64,
        proof_expires: u64,
        pin: crate::operation_once_pin::PreparedPin,
    ) -> Result<()> {
        if self.record.is_some()
            || self.entries >= crate::operation_once_ledger_scan::MAX_ENTRIES
            || self
                .bytes
                .checked_add(crate::operation_once_record::MAX_RECORD_BYTES)
                .is_none_or(|value| value > crate::operation_once_ledger_scan::MAX_TOTAL_BYTES)
        {
            return Err(PaKeyError::State);
        }
        let record = Record::prepared(&self.binding, issued, proof_expires, pin)?;
        let wire = crate::operation_once_ledger_codec::encode(&record)?;
        crate::operation_once_ledger_io::replace(
            &self.locked.directory,
            &self.binding.file_name(),
            &wire,
            false,
        )?;
        self.record = Some(record);
        Ok(())
    }

    pub(crate) fn prepared_pin(&self) -> Option<crate::operation_once_pin::PreparedPin> {
        self.record
            .as_ref()
            .map(|record| record.prepared_pin.clone())
    }

    pub(crate) fn complete(&mut self, response: &[u8]) -> Result<()> {
        let record = self.record.as_ref().ok_or(PaKeyError::State)?;
        if record.response()?.is_some() {
            return Err(PaKeyError::State);
        }
        let completed = record.complete(response)?;
        let wire = crate::operation_once_ledger_codec::encode(&completed)?;
        crate::operation_once_ledger_io::replace(
            &self.locked.directory,
            &self.binding.file_name(),
            &wire,
            true,
        )?;
        self.record = Some(completed);
        Ok(())
    }
}

pub(crate) fn recover(
    directory: &Path,
    request: &OperationAuthorizeOnceRequestV2,
    now: u64,
) -> Result<Option<Vec<u8>>> {
    Transaction::open(directory, request, now)?.response()
}
