use std::collections::HashMap;

use reqwest::Response;
use reqwest::StatusCode;
use serde::Serialize;
use url::Url;

use crate::error::Result;
use crate::error::VaultierError;
use crate::SecretClient;

const VAULT_X_TOKEN: &str = "X-Vault-Token";

pub(super) async fn set_metadata_internal(
    client: &SecretClient,
    url: Url,
    metadata: &Metadata<'_>,
) -> Result<()> {
    let response = client
        .http_client
        .post(url)
        .header(VAULT_X_TOKEN, client.token.as_ref())
        .json(metadata)
        .send()
        .await?;

    match response.status() {
        StatusCode::NO_CONTENT => Ok(()),
        status => handle_error(status, response).await,
    }
}

async fn handle_error<A>(status: StatusCode, response: Response) -> Result<A> {
    let message = response.text().await?;
    Err(VaultierError::Api { status, message })
}

#[derive(Serialize, Debug, Default)]
pub struct Metadata<'a> {
    // The number of versions to keep per key. If not set, the backend’s configured max version is used.
    // Once a key has more than the configured allowed versions, the oldest version will be permanently deleted.
    max_versions: Option<u32>,
    // If true, the key will require the cas parameter to be set on all write requests. If false,
    // the backend’s configuration will be used.
    cas_required: bool,
    // Set the delete_version_after value to a duration to specify the deletion_time for all new
    // versions written to this key. If not set, the backend's delete_version_after will be used.
    // If the value is greater than the backend's delete_version_after, the backend's
    // delete_version_after will be used.
    //
    // Accepts duration format strings: https://developer.hashicorp.com/vault/docs/concepts/duration-format
    delete_version_after: Option<&'a str>,
    // A map of arbitrary string to string valued user-provided metadata meant to describe the
    // secret.
    custom_metadata: Option<HashMap<&'a str, &'a str>>,
}

impl<'a> Metadata<'a> {
    pub fn max_versions(mut self, max_versions: u32) -> Self {
        self.max_versions = Some(max_versions);
        self
    }

    pub fn cas_required(mut self, cas_required: bool) -> Self {
        self.cas_required = cas_required;
        self
    }

    pub fn delete_version_after(mut self, delete_version_after: &'a str) -> Self {
        self.delete_version_after = Some(delete_version_after);
        self
    }

    pub fn custom_metadata(mut self, custom_metadata: HashMap<&'a str, &'a str>) -> Self {
        self.custom_metadata = Some(custom_metadata);
        self
    }
}
