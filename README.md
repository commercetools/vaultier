# Vaultier `/slɒθ/`

This crate extracts the functionality of reading secrets from vault that we used redundantly 
in three other rust driven projects.

## Usage

```rust
use vaultier::SecretClient;

struct MySecrets {
    pub username: String,
    pub password: String,
}

let address = "<vault instance address>";
let mount = String::from("<mount>");
let base_path = String::from("environment");
let client = SecretClient::new(address, mount, base_path, None).unwrap();

// read secrets from that base path
let secrets = client.read_secrets::<MySecrets>().await.unwrap();

// read secrets from the passed path relative to the base path: .../environment/my-secrets
let secrets = client.read_secrets_from::<MySecrets>("my-secrets").await.unwrap();
```
