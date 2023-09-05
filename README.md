# Vaultier `/slɒθ/` :sloth:

Small crate to read secrets from Hashicorp Vault.

## Usage

```rust
use vaultier::SecretClient;
use serde::Deserialize;

#[derive(Deserialize)]
struct MySecrets {
    pub username: String,
    pub password: String,
}

let address = "<vault instance address>";
let mount = String::from("<mount>");
let base_path = String::from("<base_path>");
let client = SecretClient::new(address, mount, base_path, None).unwrap();

// read secrets from that base path
let secrets = client.read_secrets::<MySecrets>().await.unwrap();

// read secrets from the passed path relative to the base path: mount/data/base_path/my-secrets
let secrets = client.read_secrets_from::<MySecrets>("my-secrets").await.unwrap();
```
