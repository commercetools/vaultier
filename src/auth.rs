use vaultrs::api::AuthInfo;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

use crate::error::Result;
use crate::read_token_from;

const K8S_JWT: &str = "K8S_JWT";
const SERVICE_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

pub(crate) async fn login(
    vault_address: &str,
    auth_mount_path: &str,
    role: &str,
) -> Result<AuthInfo> {
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
