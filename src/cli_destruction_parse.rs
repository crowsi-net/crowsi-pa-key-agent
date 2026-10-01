use std::path::{Path, PathBuf};

use crowsi_pa_key_agent::PaKeyError;

pub enum DestructionCommand {
    Native {
        state: PathBuf,
        credential: PathBuf,
        confirmation: String,
    },
    Preflight {
        state: PathBuf,
        credential: PathBuf,
        intent: PathBuf,
    },
    Challenge {
        state: PathBuf,
        credential: PathBuf,
        intent: PathBuf,
        challenge: PathBuf,
    },
    Finish {
        state: PathBuf,
        credential: PathBuf,
        intent: PathBuf,
        challenge: PathBuf,
        assertion: PathBuf,
    },
}

pub fn recognizes(operation: &str) -> bool {
    matches!(
        operation,
        "destroy-native"
            | "trust-domain-destroy-preflight"
            | "trust-domain-destroy-challenge"
            | "trust-domain-destroy-finish"
    )
}

pub fn parse(arguments: &[String]) -> Result<DestructionCommand, PaKeyError> {
    let operation = arguments.first().ok_or(PaKeyError::Usage)?;
    let flags = match operation.as_str() {
        "destroy-native" => &["--state", "--credential", "--confirm-public-key"][..],
        "trust-domain-destroy-preflight" => &["--state", "--credential", "--intent"][..],
        "trust-domain-destroy-challenge" => {
            &["--state", "--credential", "--intent", "--challenge"][..]
        }
        "trust-domain-destroy-finish" => &[
            "--state",
            "--credential",
            "--intent",
            "--challenge",
            "--assertion",
        ][..],
        _ => return Err(PaKeyError::Usage),
    };
    build(operation, &pairs(arguments, flags)?)
}

fn build(operation: &str, values: &[String]) -> Result<DestructionCommand, PaKeyError> {
    Ok(match operation {
        "destroy-native" => DestructionCommand::Native {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            confirmation: values[2].clone(),
        },
        "trust-domain-destroy-preflight" => DestructionCommand::Preflight {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            intent: absolute(&values[2])?,
        },
        "trust-domain-destroy-challenge" => DestructionCommand::Challenge {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            intent: absolute(&values[2])?,
            challenge: absolute(&values[3])?,
        },
        "trust-domain-destroy-finish" => DestructionCommand::Finish {
            state: absolute(&values[0])?,
            credential: absolute(&values[1])?,
            intent: absolute(&values[2])?,
            challenge: absolute(&values[3])?,
            assertion: absolute(&values[4])?,
        },
        _ => return Err(PaKeyError::Usage),
    })
}

fn pairs(arguments: &[String], flags: &[&str]) -> Result<Vec<String>, PaKeyError> {
    if arguments.len() != 1 + flags.len() * 2 {
        return Err(PaKeyError::Usage);
    }
    flags
        .iter()
        .enumerate()
        .map(|(index, flag)| {
            (arguments[1 + index * 2] == *flag)
                .then(|| arguments[2 + index * 2].clone())
                .ok_or(PaKeyError::Usage)
        })
        .collect()
}

fn absolute(value: &str) -> Result<PathBuf, PaKeyError> {
    Path::new(value)
        .is_absolute()
        .then(|| PathBuf::from(value))
        .ok_or(PaKeyError::UnsafePath)
}

#[cfg(test)]
#[path = "cli_destruction_parse_tests.rs"]
mod tests;
