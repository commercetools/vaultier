//! Vaultier is a crate to read from and write secrets to Hashicorp Vault.
//!
//!
//! ```compile_fail
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
//!
//! // With token or default feature enabled
//! let client = SecretClient::new(address, mount, base_path, None).unwrap();
//!
//! // With auth feature enabled
//! let auth_mount = "<mount to vault auth>";
//! let role = "<your role>";
//! let client = SecretClient::create(address, auth_mount, role, mount, base_path).unwrap();
//!
//! // read secrets from that base path
//! let secrets = client.read_secrets::<MySecrets>().await.unwrap();
//!
//! // read secrets from the passed path relative to the base path: mount/data/base_path/my-secrets
//! let secrets = client.read_secrets_from::<MySecrets>("my-secrets").await.unwrap();
//! ```

#[cfg(feature = "auth")]
mod auth;
pub mod error;

use std::fs::File;
use std::io::prelude::*;

use serde::Deserialize;
use vaultrs::api::kv2::responses::ReadSecretMetadataResponse;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

use crate::error::VaultierError;

#[cfg(feature = "write")]
use serde::Serialize;
#[cfg(feature = "write")]
use vaultrs::api::kv2::requests::SetSecretRequestOptions;
#[cfg(feature = "write")]
use vaultrs::api::kv2::responses::SecretVersionMetadata;

use crate::error::Result;

#[cfg(feature = "auth")]
use crate::auth::login;

#[cfg(feature = "token")]
const VAULT_TOKEN_PATH: &str = "/vault/secrets/token";

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

/// Options for confguring a write, the version will be used as cas value.
/// also see https://developer.hashicorp.com/vault/tutorials/secrets-management/versioned-kv#step-8-check-and-set-operations
pub struct WriteSecretOptions<'a, A> {
    pub data: A,
    pub path: Option<&'a str>,
    pub version: Option<u32>,
}

/// secret data including metadata
pub struct SecretWithMetaData<A> {
    pub data: A,
    pub metadata: ReadSecretMetadataResponse,
}

impl SecretClient {
    /// Convenience method to create a new SecretClient from a vault token.
    ///
    /// - address is the address of your Vault instance.
    /// - mount is the mount point of the KV2 secrets engine.
    /// - base_path reflects the lowest level of where secrets are located
    /// - token is the Vault token to use. If no token is passed it tries to read the token from /vault/secrets/token.
    #[cfg(feature = "token")]
    pub fn new(
        address: &str,
        mount: String,
        base_path: String,
        token: Option<String>,
    ) -> Result<SecretClient> {
        let token = match token {
            Some(token) => token,
            None => read_token_from(VAULT_TOKEN_PATH)?,
        };

        Self::create_internal(address, mount, base_path, &token)
    }

    /// Convenience method to create a new SecretClient with a login to vault.
    ///
    /// - address is the address of your Vault instance
    /// - auth_mount is the mount path of the vault authentication
    /// - role is the vault role to use for the login
    /// - mount is the mount point of the KV2 secrets engine
    /// - base_path reflects the lowest level of where secrets are located
    #[cfg(feature = "auth")]
    pub async fn create(
        address: &str,
        auth_mount: &str,
        role: &str,
        mount: String,
        base_path: String,
    ) -> Result<SecretClient> {
        let auth = login(address, auth_mount, role).await?;

        Self::create_internal(address, mount, base_path, &auth.client_token)
    }

    fn create_internal(
        address: &str,
        mount: String,
        base_path: String,
        token: &str,
    ) -> Result<SecretClient> {
        let client = VaultClient::new(
            VaultClientSettingsBuilder::default()
                .address(address)
                .token(token)
                .build()?,
        )?;

        Ok(SecretClient { client, mount, base_path })
    }

    /// Read secrets from the base path.
    #[cfg(feature = "read")]
    pub async fn read_secrets<A>(&self) -> Result<A>
    where
        A: for<'de> Deserialize<'de>,
    {
        self.read_secrets_internal::<A>(&self.base_path, None).await
    }

    /// Read secrets from the passed path relative to the base path.
    #[cfg(feature = "read")]
    pub async fn read_secrets_from<A>(&self, path: &str) -> Result<A>
    where
        A: for<'de> Deserialize<'de>,
    {
        let path = format!("{}/{}", self.base_path, path);
        self.read_secrets_internal::<A>(&path, None).await
    }

    /// Read secrets with metadata.
    #[cfg(feature = "read")]
    pub async fn read_secrets_with_metadata<A>(
        &self,
        path: Option<&str>,
    ) -> Result<SecretWithMetaData<A>>
    where
        A: for<'de> Deserialize<'de>,
    {
        let path = path.unwrap_or(&self.base_path);
        let metadata: vaultrs::api::kv2::responses::ReadSecretMetadataResponse =
            kv2::read_metadata(&self.client, &self.mount, path).await?;

        let data = self
            .read_secrets_internal(path, Some(metadata.current_version))
            .await?;

        Ok(SecretWithMetaData { data, metadata })
    }

    #[cfg(feature = "read")]
    async fn read_secrets_internal<A>(&self, path: &str, version: Option<u64>) -> Result<A>
    where
        A: for<'de> Deserialize<'de>,
    {
        let secrets = match version {
            Some(version) => kv2::read_version::<A>(&self.client, &self.mount, path, version).await,
            None => kv2::read::<A>(&self.client, &self.mount, path).await,
        };

        if let Err(ClientError::APIError { code: 404, .. }) = secrets {
            return Err(VaultierError::PathNotFound(format!(
                "{mount}/data/{path}",
                mount = self.mount
            )));
        }

        Ok(secrets?)
    }

    /// Set secrets in the base path.
    #[cfg(feature = "write")]
    pub async fn set_secrets<A>(&self, data: &A) -> Result<SecretVersionMetadata>
    where
        A: Serialize,
    {
        self.set_secrets_internal(&self.base_path, data).await
    }

    /// Set secrets in the base path.
    #[cfg(feature = "write")]
    pub async fn set_secrets_in<A>(&self, path: &str, data: &A) -> Result<SecretVersionMetadata>
    where
        A: Serialize,
    {
        let path = format!("{}/{}", self.base_path, path);
        self.set_secrets_internal(&path, data).await
    }

    #[cfg(feature = "write")]
    pub async fn set_secrets_internal<A>(
        &self,
        path: &str,
        data: &A,
    ) -> Result<SecretVersionMetadata>
    where
        A: Serialize,
    {
        let auth_info = kv2::set(&self.client, &self.mount, path, data).await?;
        Ok(auth_info)
    }

    #[cfg(feature = "write")]
    pub async fn set_secrets_with_options<A>(
        &self,
        options: WriteSecretOptions<'_, A>,
    ) -> Result<SecretVersionMetadata>
    where
        A: Serialize,
    {
        let path = options.path.unwrap_or_else(|| &self.base_path);

        let auth_info = match options.version {
            Some(cas) => {
                kv2::set_with_options(
                    &self.client,
                    &self.mount,
                    path,
                    &options.data,
                    SetSecretRequestOptions { cas },
                )
                .await?
            }
            None => kv2::set(&self.client, &self.mount, path, &options.data).await?,
        };

        Ok(auth_info)
    }
}

fn read_token_from(path: &str) -> Result<String> {
    let mut file = File::open(path)?;
    let mut token = String::new();
    file.read_to_string(&mut token)?;
    Ok(token)
}
