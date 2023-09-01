use std::fmt::{Debug, Formatter};
use std::{fmt, io};

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug)]
pub enum VaultError {
    VaultClient(vaultrs::error::ClientError),
    VaultClientSettings(vaultrs::client::VaultClientSettingsBuilderError),
    IO(io::Error),
}

impl std::error::Error for VaultError {}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::VaultClient(e) => std::fmt::Display::fmt(e, f),
            VaultError::VaultClientSettings(e) => std::fmt::Display::fmt(e, f),
            VaultError::IO(e) => std::fmt::Display::fmt(e, f),
        }
    }
}

impl From<vaultrs::error::ClientError> for VaultError {
    fn from(vault_client_error: vaultrs::error::ClientError) -> Self {
        VaultError::VaultClient(vault_client_error)
    }
}

impl From<vaultrs::client::VaultClientSettingsBuilderError> for VaultError {
    fn from(settingsbuilder_error: vaultrs::client::VaultClientSettingsBuilderError) -> Self {
        VaultError::VaultClientSettings(settingsbuilder_error)
    }
}

impl From<io::Error> for VaultError {
    fn from(error: io::Error) -> Self {
        VaultError::IO(error)
    }
}
