//! Vaultier is a crate to read from and write secrets to Hashicorp Vault.
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

use serde::{Deserialize, Serialize};
use vaultrs::api::kv2::responses::SecretVersionMetadata;
use vaultrs::api::AuthInfo;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

use crate::error::Result;

const VAULT_TOKEN_PATH: &str = "/vault/secrets/token";
const K8S_JWT: &str = "K8S_JWT";
const SERVICE_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

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
    /// Convenience method to create a new SecretClient from a vault token.
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
            None => read_token_from(VAULT_TOKEN_PATH)?,
        };

        Self::create_internal(address, mount, base_path, &token)
    }

    /// Convenience method to create a new SecretClient with a login to vault.
    ///
    /// - address is the address of your Vault instance
    /// - auth_mount is the mount path of the vault authentication
    /// - mount is the mount point of the KV2 secrets engine
    /// - base_path reflects the lowest level of where secrets are located
    /// - role is the vault role to use for the login
    pub async fn create(
        address: &str,
        auth_mount: &str,
        mount: String,
        base_path: String,
        role: &str,
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

    /// Set secrets in the base path.
    pub async fn set_secrets<A>(&self, data: &A) -> Result<SecretVersionMetadata>
    where
        A: Serialize,
    {
        self.set_secrets_internal(&self.base_path, data).await
    }

    /// Set secrets in the base path.
    pub async fn set_secrets_in<A>(&self, path: &str, data: &A) -> Result<SecretVersionMetadata>
    where
        A: Serialize,
    {
        let path = format!("{}/{}", self.base_path, path);
        self.set_secrets_internal(&path, data).await
    }

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
}

fn read_token_from(path: &str) -> Result<String> {
    let mut file = File::open(path)?;
    let mut token = String::new();
    file.read_to_string(&mut token)?;
    Ok(token)
}

async fn login(vault_address: &str, auth_mount_path: &str, role: &str) -> Result<AuthInfo> {
    let jwt = service_account_jwt()?;
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(vault_address)
            .build()?,
    )?;
    Ok(vaultrs::auth::kubernetes::login(&client, auth_mount_path, role, &jwt).await?)
}

fn service_account_jwt() -> Result<String> {
    let env_token = std::env::var(K8S_JWT);

    match env_token {
        Ok(token) => Ok(token),
        Err(_) => read_token_from(SERVICE_TOKEN_PATH),
    }
}
