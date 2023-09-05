//! Vaultier is a crate to read secrets from Hashicorp Vault.
//!
//!
//! ``` compile_fail
//! use vaultier::SecretClient;
//!
//! #[derive(serde::Deserialize)]
//! struct MySecrets {
//!     pub username: String,
//!     pub password: String,
//! }
//!
//! let address = "<vault instance address>";
//! let mount = String::from("<mount>");
//! let base_path = String::from("<base_path>");
//! let client = SecretClient::new(address, mount, base_path, None).unwrap();
//!
//! // read secrets from that base path
//! let secrets = client.read_secrets::<MySecrets>().await.unwrap();
//!
//! // read secrets from the passed path relative to the base path: mount/data/base_path/my-secrets
//! let secrets = client.read_secrets_from::<MySecrets>("my-secrets").await.unwrap();
//! ```

pub mod error;

use std::fs::File;
use std::io::prelude::*;

use serde::Deserialize;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

use crate::error::Result;

const TOKEN_PATH: &str = "/vault/secrets/token";

/// A client to read secrets from Hashicorp Vault.
///
/// The client is initialized with a VaultClient, the mount and a base path.
///
/// <mount>/data/<base_path> where base_path reflects the lowest level of where secrets are located.
pub struct SecretClient {
    client: VaultClient,
    mount: String,
    base_path: String,
}

impl SecretClient {
    /// Convenience method to create a new SecretClient.
    ///
    /// - address is the address of your Vault instance.
    /// - mount is the mount point of the KV2 secrets engine.
    /// - base_path reflects the lowest level of where secrets are located
    /// - token is the Vault token to use. If no token is passed it tries to read the token from /vault/secrets/token.
    pub fn new(
        address: &str,
        mount: String,
        base_path: String,
        token: Option<String>,
    ) -> Result<SecretClient> {
        let token = match token {
            Some(token) => token,
            None => read_vault_token(TOKEN_PATH)?,
        };

        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(address)
                .token(token)
                .build()?,
        )?;

        Ok(SecretClient { client, mount, base_path })
    }

    /// Read secrets from the passed path relative to the base path.
    pub async fn read_secrets_from<A>(&self, path: &str) -> Result<A>
    where
        A: for<'de> Deserialize<'de>,
    {
        let path = format!("{}/{}", self.base_path, path);
        self.read_secrets_internal::<A>(&path).await
    }

    /// Read secrets from the base path.
    pub async fn read_secrets<A>(&self) -> Result<A>
    where
        A: for<'de> Deserialize<'de>,
    {
        self.read_secrets_internal::<A>(&self.base_path).await
    }

    async fn read_secrets_internal<A>(&self, path: &str) -> Result<A>
    where
        A: for<'de> Deserialize<'de>,
    {
        let secrets: A = kv2::read(&self.client, &self.mount, path).await?;
        Ok(secrets)
    }
}

fn read_vault_token(path: &str) -> Result<String> {
    let mut file = File::open(path)?;
    let mut token = String::new();
    file.read_to_string(&mut token)?;
    Ok(token)
}
