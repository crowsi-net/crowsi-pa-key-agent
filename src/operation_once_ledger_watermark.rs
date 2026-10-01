use serde::{Deserialize, Serialize};

use crate::{PaKeyError, Result};

const SCHEMA: &str = "crowsi://policy-authority/operation-once-time-watermark/v1";
const MAX_BYTES: u64 = 256;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Watermark {
    schema: String,
    greatest_observed_epoch_s: u64,
}

pub(crate) fn advance(
    directory: &crate::operation_once_ledger_dir::LedgerDir,
    now: u64,
) -> Result<()> {
    let exists = directory
        .names()?
        .iter()
        .any(|name| name == crate::operation_once_ledger_dir::WATERMARK_NAME);
    if exists {
        let wire = directory.read(
            crate::operation_once_ledger_dir::WATERMARK_NAME,
            MAX_BYTES,
            1,
        )?;
        let current = decode(&wire)?;
        if now < current.greatest_observed_epoch_s {
            return Err(PaKeyError::State);
        }
        if now == current.greatest_observed_epoch_s {
            return Ok(());
        }
    }
    let wire = encode(now)?;
    crate::operation_once_ledger_io::replace(
        directory,
        crate::operation_once_ledger_dir::WATERMARK_NAME,
        &wire,
        exists,
    )
}

fn encode(now: u64) -> Result<Vec<u8>> {
    serde_json::to_vec(&Watermark {
        schema: SCHEMA.into(),
        greatest_observed_epoch_s: now,
    })
    .map_err(|_| PaKeyError::Encoding)
}

fn decode(wire: &[u8]) -> Result<Watermark> {
    let mut decoder = serde_json::Deserializer::from_slice(wire);
    let value: Watermark =
        serde::Deserialize::deserialize(&mut decoder).map_err(|_| PaKeyError::State)?;
    decoder.end().map_err(|_| PaKeyError::State)?;
    let exact = value.schema == SCHEMA
        && value.greatest_observed_epoch_s > 0
        && encode(value.greatest_observed_epoch_s)? == wire;
    exact.then_some(value).ok_or(PaKeyError::State)
}
