use std::fmt::{Debug, Formatter};
use std::{fmt, io};

pub type Result<T> = std::result::Result<T, VaultierError>;

#[derive(Debug)]
pub enum VaultierError {
    VaultClient(vaultrs::error::ClientError),
    VaultClientSettings(vaultrs::client::VaultClientSettingsBuilderError),
    IO(io::Error),
}

impl std::error::Error for VaultierError {}

impl fmt::Display for VaultierError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VaultierError::VaultClient(e) => std::fmt::Display::fmt(e, f),
            VaultierError::VaultClientSettings(e) => std::fmt::Display::fmt(e, f),
            VaultierError::IO(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl From<vaultrs::error::ClientError> for VaultierError {
    fn from(vault_client_error: vaultrs::error::ClientError) -> Self {
        VaultierError::VaultClient(vault_client_error)
    }
}

impl From<vaultrs::client::VaultClientSettingsBuilderError> for VaultierError {
    fn from(settingsbuilder_error: vaultrs::client::VaultClientSettingsBuilderError) -> Self {
        VaultierError::VaultClientSettings(settingsbuilder_error)
    }
}

impl From<io::Error> for VaultierError {
    fn from(error: io::Error) -> Self {
        VaultierError::IO(error)
    }
}
