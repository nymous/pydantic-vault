# Pydantic-Vault

![Check code](https://github.com/nymous/pydantic-vault/workflows/Check%20code/badge.svg)

A simple extension to [Pydantic][pydantic] [BaseSettings][pydantic-basesettings] that can retrieve secrets from a [KV v2 secrets engine][vault-kv-v2] in Hashicorp [Vault][vault]

## Getting started

Starting with Pydantic 1.8, [custom settings sources][pydantic-basesettings-customsource] are officially supported.

You can create a normal `BaseSettings` class, and define the `customise_sources()` method to load secrets from your Vault instance using the `vault_config_settings_source` function:

```python
import os

from pydantic import BaseSettings, Field, SecretStr
from pydantic_vault import vault_config_settings_source

class Settings(BaseSettings):
    username: str = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_user")
    password: SecretStr = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_password")

    class Config:
        vault_url: str = "https://vault.tld"
        vault_token: SecretStr = os.environ["VAULT_TOKEN"]
        vault_namespace: str = "your/namespace"  # Optional, pydantic-vault supports Vault namespaces (for Vault Enterprise)
        vault_secret_mount_point: str = "secrets"  # Optional, if your KV v2 secrets engine is not available at the default "secret" mount point

        @classmethod
        def customise_sources(
                cls,
                init_settings,
                env_settings,
                file_secret_settings,
        ):
            # This is where you can choose which settings sources to use and their priority
            return (
                init_settings,
                env_settings,
                vault_config_settings_source,
                file_secret_settings
            )

settings = Settings()
# These variables will come from the Vault secret you configured
settings.username
settings.password.get_secret_value()


# Now let's pretend we have already set the USERNAME in an environment variable
# (see the Pydantic documentation for more information and to know how to configure it)
# With the priority order we defined above, its value will override the Vault secret
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

### Configuration

You can configure the behaviour of Pydantic-vault in your `Settings.Config` class, or using environment variables:

| Settings name              | Required | Environment variable | Description |
|----------------------------|----------|----------------------|-------------|
| `customise_sources()`      | **Yes**  | N/A                  | You need to implement this function to use Vault as a settings source, and choose the priority order you want |
| `vault_url`                | **Yes**  | `VAULT_ADDR`         | Your Vault URL |
| `vault_namespace`          | No       | `VAULT_NAMESPACE`    | Your Vault namespace (if you use one, requires Vault Enterprise) |
| `vault_secret_mount_point` | No       | N/A                  | The mount point of the KV v2 secrets engine, if different from the default `"secret"` mount point |

You can also configure everything available in the original Pydantic `BaseSettings` class.

### Authentication

For now Pydantic-Vault only supports direct token authentication, that is you must authenticate using your method of choice then pass the resulting Vault token to your `Settings` class.

Support is planned for Approle and Kubernetes authentication methods.

#### Vault token

To authenticate using the [Token auth method][vault-auth-token], you need to pass a Vault token to your `Settings` class.

Pydantic-vault reads this token from the following sources (in decreasing order of priority):
  - the `VAULT_TOKEN` environment variable
  - the `~/.vault-token` file
  - the `vault_token` configuration field in your `Settings.Config` class, which can be a `str` or a `SecretStr`

```python
from pydantic import BaseSettings, Field, SecretStr
from pydantic_vault import vault_config_settings_source

class Settings(BaseSettings):
    username: str = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_user")
    password: SecretStr = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_password")

    class Config:
        vault_url: str = "https://vault.tld"
        vault_token: SecretStr = SecretStr("my-secret-token")

        @classmethod
        def customise_sources(
                cls,
                init_settings,
                env_settings,
                file_secret_settings,
        ):
            return (
                init_settings,
                env_settings,
                vault_config_settings_source,
                file_secret_settings
            )
```

### Order of priority

Thanks to the new feature in Pydantic 1.8 that allows you to [customize settings sources][pydantic-basesettings-customsource], you can choose the order of priority you want.

Here are some examples:
```python
from pydantic import BaseSettings
from pydantic_vault import vault_config_settings_source

class Settings(BaseSettings):
    """
    In descending order of priority:
      - arguments passed to the `Settings` class initializer
      - environment variables
      - Vault variables
      - variables loaded from the secrets directory, such as Docker Secrets
      - the default field values for the `Settings` model
    """
    class Config:
        @classmethod
        def customise_sources(
                cls,
                init_settings,
                env_settings,
                file_secret_settings,
        ):
            return (
                init_settings,
                env_settings,
                vault_config_settings_source,
                file_secret_settings
            )


class Settings(BaseSettings):
    """
    In descending order of priority:
      - Vault variables
      - environment variables
      - variables loaded from the secrets directory, such as Docker Secrets
      - the default field values for the `Settings` model
    Here we chose to remove the "init arguments" source,
    and move the Vault source up before the environment source
    """
    class Config:
        @classmethod
        def customise_sources(
                cls,
                init_settings,
                env_settings,
                file_secret_settings,
        ):
            return (
                vault_config_settings_source,
                env_settings,
                file_secret_settings
            )
```

## Inspirations

- [Ansible `hashi_vault` lookup plugin][ansible hashi_vault] for the API and some code
- [Hashicorp's Vault GitHub Action][vault-action] for the API

## License

Pydantic-Vault is available under the [MIT license](./LICENSE).

[ansible hashi_vault]: https://docs.ansible.com/ansible/latest/collections/community/hashi_vault/hashi_vault_lookup.html
[pydantic]: https://pydantic-docs.helpmanual.io/
[pydantic-basesettings]: https://pydantic-docs.helpmanual.io/usage/settings/
[pydantic-basesettings-customsource]: https://pydantic-docs.helpmanual.io/usage/settings/#customise-settings-sources
[vault]: https://www.vaultproject.io/
[vault-action]: https://github.com/hashicorp/vault-action
[vault-auth-token]: https://www.vaultproject.io/docs/auth/token
[vault-kv-v2]: https://www.vaultproject.io/docs/secrets/kv/kv-v2/
