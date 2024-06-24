use std::fmt::Debug;
use std::io;

use thiserror::Error;

pub type Result<T> = std::result::Result<T, VaultierError>;

#[derive(Error, Debug)]
pub enum VaultierError {
    #[error("Vault client error: {0}")]
    VaultClient(#[from] vaultrs::error::ClientError),
    #[error("Vault client settings error: {0}")]
    VaultClientSettings(#[from] vaultrs::client::VaultClientSettingsBuilderError),
    #[error("IO error: {0}")]
    IO(#[from] io::Error),
    #[error("Path not found: {0}")]
    PathNotFound(String),
}
