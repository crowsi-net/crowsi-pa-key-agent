use std::path::{Path, PathBuf};

use crate::PaKeyError;
use crate::cli_destruction_parse::{DestructionCommand, recognizes};

pub enum RegistrationCommand {
    Challenge {
        state: PathBuf,
        challenge: PathBuf,
        rp_id: String,
        origin: String,
    },
    Stage {
        state: PathBuf,
        challenge: PathBuf,
        response: PathBuf,
        candidate: PathBuf,
        proof_challenge: PathBuf,
        credential: PathBuf,
    },
    Confirm {
        state: PathBuf,
        candidate: PathBuf,
        proof_challenge: PathBuf,
        assertion: PathBuf,
        credential: PathBuf,
    },
}

pub enum Command {
    State {
        operation: String,
        state: PathBuf,
    },
    Destruction(DestructionCommand),
    PasskeyStatus {
        state: PathBuf,
        credential: PathBuf,
    },
    PasskeyRecoveryRevoke {
        state: PathBuf,
        credential: PathBuf,
        expected_public_key: String,
        confirmation: String,
    },
    PasskeyAuthenticationChallenge {
        state: PathBuf,
        credential: PathBuf,
        challenge: PathBuf,
    },
    PasskeyAuthenticate {
        state: PathBuf,
        credential: PathBuf,
        challenge: PathBuf,
        assertion: PathBuf,
    },
    Registration(RegistrationCommand),
    RebindChallenge {
        state: PathBuf,
        credential: PathBuf,
        challenge: PathBuf,
    },
    Rebind {
        state: PathBuf,
        credential: PathBuf,
        challenge: PathBuf,
        assertion: PathBuf,
    },
    AuthorizationChallenge {
        state: PathBuf,
        credential: PathBuf,
        request: PathBuf,
        identity_assertion: PathBuf,
        identity_status: PathBuf,
        identity_trust: PathBuf,
        challenge: PathBuf,
        origin: String,
    },
    Authorize {
        state: PathBuf,
        credential: PathBuf,
        challenge: PathBuf,
        assertion: PathBuf,
        request: PathBuf,
        identity_assertion: PathBuf,
        identity_status: PathBuf,
        identity_trust: PathBuf,
        output: PathBuf,
    },
}

pub struct ParsedCommand {
    pub command: Command,
    pub custody: PathBuf,
}

pub fn parse(arguments: &[String]) -> Result<ParsedCommand, PaKeyError> {
    let (command_arguments, custody) = custody_argument(arguments)?;
    let command = parse_command(command_arguments)?;
    Ok(ParsedCommand { command, custody })
}

fn parse_command(arguments: &[String]) -> Result<Command, PaKeyError> {
    let operation = arguments.first().ok_or(PaKeyError::Usage)?;
    if recognizes(operation) {
        return crate::cli_destruction_parse::parse(arguments).map(Command::Destruction);
    }
    if let Some(command) = crate::cli_passkey_parse::parse(arguments)? {
        return Ok(command);
    }
    let values = match operation.as_str() {
        "doctor" | "initialize" | "status" => pairs(arguments, &["--state"]),
        _ => return Err(PaKeyError::Usage),
    }?;
    build(operation, &values)
}

fn custody_argument(arguments: &[String]) -> Result<(&[String], PathBuf), PaKeyError> {
    if arguments.len() < 3 || arguments[arguments.len() - 2] != "--custody" {
        return Err(PaKeyError::Usage);
    }
    let custody = absolute(&arguments[arguments.len() - 1])?;
    Ok((&arguments[..arguments.len() - 2], custody))
}

fn build(operation: &str, values: &[String]) -> Result<Command, PaKeyError> {
    Ok(match operation {
        "doctor" | "initialize" | "status" => Command::State {
            operation: operation.into(),
            state: absolute(&values[0])?,
        },
        _ => return Err(PaKeyError::Usage),
    })
}

pub(crate) fn pairs(arguments: &[String], flags: &[&str]) -> Result<Vec<String>, PaKeyError> {
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

pub(crate) fn absolute(value: &str) -> Result<PathBuf, PaKeyError> {
    Path::new(value)
        .is_absolute()
        .then(|| PathBuf::from(value))
        .ok_or(PaKeyError::UnsafePath)
}
