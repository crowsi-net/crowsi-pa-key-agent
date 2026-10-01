use crate::{PaKeyError, Result, operation_once_record::Record};

pub(crate) fn encode(value: &Record) -> Result<Vec<u8>> {
    value.validate()?;
    let wire = serde_json::to_vec(value).map_err(|_| PaKeyError::Encoding)?;
    bounded(&wire)?;
    Ok(wire)
}

pub(crate) fn decode(wire: &[u8]) -> Result<Record> {
    bounded(wire)?;
    let mut decoder = serde_json::Deserializer::from_slice(wire);
    let value: Record =
        serde::Deserialize::deserialize(&mut decoder).map_err(|_| PaKeyError::State)?;
    decoder.end().map_err(|_| PaKeyError::State)?;
    value.validate()?;
    (encode(&value)? == wire)
        .then_some(value)
        .ok_or(PaKeyError::State)
}

fn bounded(wire: &[u8]) -> Result<()> {
    (!wire.is_empty()
        && u64::try_from(wire.len()).ok() <= Some(crate::operation_once_record::MAX_RECORD_BYTES))
    .then_some(())
    .ok_or(PaKeyError::State)
}
