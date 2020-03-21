# Pydantic-Vault

![Check code](https://github.com/nymous/pydantic-vault/workflows/Check%20code/badge.svg)

A simple extension to [Pydantic][pydantic] [BaseSettings][pydantic-basesettings] that can retrieve secrets from a [KV v2 secrets engine][vault-kv-v2] in Hashicorp [Vault][vault]

## Getting started

Same as with the Pydantic `BaseSettings`, create a class that inherits from `pydantic_vault.VaultBaseSettings`, then define your fields and configure the settings with

```python
import os

from pydantic import SecretStr, Field
from pydantic_vault import VaultBaseSettings

class Settings(VaultBaseSettings):
    username: str = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_user")
    password: SecretStr = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_password")

    class Config:
        vault_url: str = "https://vault.tld"
        vault_token: SecretStr = os.environ["VAULT_TOKEN"]
        vault_namespace: str = "your/namespace"  # Optional, pydantic-vault supports Vault namespaces (for Vault Enterprise)
        vault_secret_mount_point: str = "secrets"  # Optional, if your KV v2 secrets engine is not available at the default "secret" mount point

settings = Settings()
# These variables will come from the Vault secret you configured
settings.username
settings.password.get_secret_value()


# Now let's pretend we have already set the USERNAME in an environment variable
# (see the Pydantic documentation for more information and to know how to configure it)
# Its value will override the Vault secret
os.environ["USERNAME"] = "my user"

settings = Settings()
settings.username  # "my user", defined in the environment variable
settings.password.get_secret_value()  # the value set in Vault
```

## Documentation

### `Field` additional parameters

You might have noticed that we import `Field` directly from Pydantic. Pydantic-Vault doesn't add any custom logic to it, which means you can still use everything you know and love from Pydantic.

The additional parameters Pydantic-Vault uses are:

| Parameter name              | Required | Description |
|-----------------------------|----------|-------------|
| `vault_secret_path`         | **Yes**  | The path to your secret in Vault |
| `vault_secret_key`          | **Yes**  | The key to use in the secret |

For example, if you create a secret `database/prod` with a key `password` and a value of `a secret password`, you would use

```python
password: SecretStr = Field(..., vault_secret_path="database/prod", vault_secret_key="password")
```

### Authentication

For now Pydantic-Vault only supports direct token authentication, that is you must authenticate using your method of choice then pass the resulting Vault token to your `Settings` class.

Support is planned for Approle and Kubernetes authentication methods.

### Configuration

In your `Settings.Config` class you can configure the following elements:

| Settings name              | Required | Description |
|----------------------------|----------|-------------|
| `vault_url`                | **Yes**  | Your Vault URL |
| `vault_token`              | **Yes**  | A token allowing to connect to Vault (retrieve it with any auth method you want) |
| `vault_namespace`          | No       | Your Vault namespace (if you use one, requires Vault Enterprise) |
| `vault_secret_mount_point` | No       | The mount point of the KV v2 secrets engine, if different from the default `"secret"` mount point |

You can also configure everything available in the original Pydantic `BaseSettings` class.

### Order of priority

Settings values are determined as follows (in descending order of priority):
  - arguments passed to the `Settings` class initializer
  - environment variables
  - Vault variables
  - the default field values for the `Settings` model

It's the [same order][pydantic-basesettings-priority] as with the original `BaseSettings`, but with Vault just before the default values.


## License

Pydantic-Vault is available under the [MIT license](./LICENSE).

[pydantic]: https://pydantic-docs.helpmanual.io/
[pydantic-basesettings]: https://pydantic-docs.helpmanual.io/usage/settings/
[pydantic-basesettings-priority]: https://pydantic-docs.helpmanual.io/usage/settings/#field-value-priority
[vault]: https://www.vaultproject.io/
[vault-kv-v2]: https://www.vaultproject.io/docs/secrets/kv/kv-v2/
