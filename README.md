# Pydantic-Vault

[![PyPI](https://img.shields.io/pypi/v/pydantic-vault)](https://pypi.org/project/pydantic-vault/)
[![Check code](https://github.com/nymous/pydantic-vault/workflows/Check%20code/badge.svg)](https://github.com/nymous/pydantic-vault/actions/workflows/check_code.yml)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A simple extension to [Pydantic][pydantic] [BaseSettings][pydantic-basesettings] that can retrieve secrets from a [KV v2 secrets engine][vault-kv-v2] in Hashicorp [Vault][vault]

↖️ *Hint: look at the table of contents up there! (<svg aria-hidden="true" viewBox="0 0 16 16" version="1.1" data-view-component="true" height="16" width="16" class="octicon octicon-list-unordered">
    <path fill-rule="evenodd" d="M2 4a1 1 0 100-2 1 1 0 000 2zm3.75-1.5a.75.75 0 000 1.5h8.5a.75.75 0 000-1.5h-8.5zm0 5a.75.75 0 000 1.5h8.5a.75.75 0 000-1.5h-8.5zm0 5a.75.75 0 000 1.5h8.5a.75.75 0 000-1.5h-8.5zM3 8a1 1 0 11-2 0 1 1 0 012 0zm-1 6a1 1 0 100-2 1 1 0 000 2z"></path>
</svg> icon above the Readme on GitHub)*

## Getting started

Starting with Pydantic 1.8, [custom settings sources][pydantic-basesettings-customsource] are officially supported.

You can create a normal `BaseSettings` class, and define the `customise_sources()` method to load secrets from your Vault instance using the `vault_config_settings_source` function:

```python
import os

from pydantic import BaseSettings, Field, SecretStr
from pydantic_vault import vault_config_settings_source

class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret
    # The `vault_secret_key` is the specific key to extract from a secret
    username: str = Field(..., vault_secret_path="secret/data/path/to/secret", vault_secret_key="my_user")
    password: SecretStr = Field(..., vault_secret_path="secret/data/path/to/secret", vault_secret_key="my_password")

    class Config:
        vault_url: str = "https://vault.tld"
        vault_token: SecretStr = os.environ["VAULT_TOKEN"]
        vault_namespace: str = "your/namespace"  # Optional, pydantic-vault supports Vault namespaces (for Vault Enterprise)

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
| `vault_secret_path`         | **Yes**  | The path to your secret in Vault<br>This needs to be the *full path* to the secret, including its mount point (see [examples](#examples) below) |
| `vault_secret_key`          | No       | The key to use in the secret<br>If it is not specified the whole secret content will be loaded as a dict (see [examples](#examples) below) |

For example, if you create a secret `database/prod` with a key `password` and a value of `a secret password` in a KV v2 secret engine mounted at the default `secret/` location, you would access it with

```python
password: SecretStr = Field(..., vault_secret_path="secret/data/database/prod", vault_secret_key="password")
```

### Configuration

You can configure the behaviour of Pydantic-vault in your `Settings.Config` class, or using environment variables:

| Settings name              | Required | Environment variable | Description |
|----------------------------|----------|----------------------|-------------|
| `customise_sources()`      | **Yes**  | N/A                  | You need to implement this function to use Vault as a settings source, and choose the priority order you want |
| `vault_url`                | **Yes**  | `VAULT_ADDR`         | Your Vault URL |
| `vault_namespace`          | No       | `VAULT_NAMESPACE`    | Your Vault namespace (if you use one, requires Vault Enterprise) |
| `vault_auth_mount_point`   | No       | `VAULT_AUTH_MOUNT_POINT` | The mount point of the authentication method, if different from its default mount point |

You can also configure everything available in the original Pydantic `BaseSettings` class.

### Authentication

For now Pydantic-Vault supports the following authentication method (in descending order of priority):
  - [direct token authentication][vault-auth-token]
  - [kubernetes][vault-auth-kubernetes]
  - [approle][vault-auth-approle]

Support is planned for GKE authentication methods.

#### Approle

To authenticate using the [Approle auth method][vault-auth-approle], you need to pass a role ID and a secret ID to your Settings class.

Pydantic-vault reads this information from the following sources (in descending order of priority):
  - the `vault_role_id` and `vault_secret_id` configuration fields in your `Settings.Config` class (`vault_secret_id` can be a `str` or a `SecretStr`)
  - the `VAULT_ROLE_ID` and `VAULT_SECRET_ID` environment variables

You can also mix-and-match, e.g. write the role ID in your `Settings.Config` class and retrieve the secret ID from the environment at runtime.

Example:
```python
from pydantic import BaseSettings, Field, SecretStr
from pydantic_vault import vault_config_settings_source

class Settings(BaseSettings):
    username: str = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_user")
    password: SecretStr = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_password")

    class Config:
        vault_url: str = "https://vault.tld"
        vault_role_id: str = "my-role-id"
        vault_secret_id_id: SecretStr = SecretStr("my-secret-id")

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

#### Kubernetes

To authenticate using the [Kubernetes auth method][vault-auth-kubernetes], you need to pass a role to your Settings class.

Pydantic-vault reads this information from the following sources (in descending order of priority):
  - the `vault_kubernetes_role` configuration field in your `Settings.Config` class, which must be a `str`
  - the `VAULT_KUBERNETES_ROLE` environment variable

The Kubernetes service account token will be read from the file at `/var/run/secrets/kubernetes.io/serviceaccount/token`.

Example:
```python
from pydantic import BaseSettings, Field, SecretStr
from pydantic_vault import vault_config_settings_source

class Settings(BaseSettings):
    username: str = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_user")
    password: SecretStr = Field(..., vault_secret_path="path/to/secret", vault_secret_key="my_password")

    class Config:
        vault_url: str = "https://vault.tld"
        vault_kubernetes_role: str = "my-role"

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

#### Vault token

To authenticate using the [Token auth method][vault-auth-token], you need to pass a Vault token to your `Settings` class.

Pydantic-vault reads this token from the following sources (in descending order of priority):
  - the `vault_token` configuration field in your `Settings.Config` class, which can be a `str` or a `SecretStr`
  - the `VAULT_TOKEN` environment variable
  - the `~/.vault-token` file (so you can use the `vault` CLI to login locally, Pydantic-vault will transparently reuse its token)

Example:
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

## Examples

All examples use the following structure, so we will omit the imports and the `Config` inner class:
```python
from pydantic import BaseSettings, Field, SecretStr
from pydantic_vault import vault_config_settings_source

class Settings(BaseSettings):
    ###############################################
    # THIS PART CHANGES IN THE DIFFERENT EXAMPLES #
    username: str = Field(..., vault_secret_path="secret/data/path/to/secret", vault_secret_key="my_user")
    ###############################################

    class Config:
        vault_url: str = "https://vault.tld"

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

### Retrieve a secret from a KV v2 secret engine

Suppose your secret is at `my-api/prod` and looks like this:
```
Key             Value
---             -----
root_user       root
root_password   a_v3ry_s3cur3_p4ssw0rd
```

Your settings class would be:
```python
class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v2 secret engine, there is always a `data/` sub-path between the mount point and
    # the secret actual path, eg. if your mount point is `secret/` (the default) and your secret
    # path is `my-api/prod`, the full path to use is `secret/data/my-api/prod`.
    # The `vault_secret_key` is the specific key to extract from a secret.
    username: str = Field(..., vault_secret_path="secret/data/my-api/prod", vault_secret_key="root_user")
    password: SecretStr = Field(..., vault_secret_path="secret/data/my-api/prod", vault_secret_key="root_password")

settings = Settings()

settings.username  # "root"
settings.password.get_secret_value()  # "a_v3ry_s3cur3_p4ssw0rd"
```

### Retrieve a whole secret at once

If you omit the `vault_secret_key` parameter in your `Field`, Pydantic-Vault will load
the whole secret in your class field.

With the same secret as before, located at `my-api/prod` and with this data:
```
Key             Value
---             -----
root_user       root
root_password   a_v3ry_s3cur3_p4ssw0rd
```

You could use a settings class like this to retrieve everything in the secret:
```python
class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v2 secret engine, there is always a `data/` sub-path between the mount point and
    # the secret actual path, eg. if your mount point is `secret/` (the default) and your secret
    # path is `my-api/prod`, the full path to use is `secret/data/my-api/prod`.
    # We don't pass a `vault_secret_key` here so that Pydantic-Vault fetches all fields at once.
    credentials: dict = Field(..., vault_secret_path="secret/data/my-api/prod")

settings = Settings()
settings.credentials  # { "root_user": "root", "root_password": "a_v3ry_s3cur3_p4ssw0rd" }
```

You can also use a Pydantic `BaseModel` class to parse and validate the incoming secret:
```python
class Credentials(BaseModel):
    root_user: str
    root_password: SecretStr

class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v2 secret engine, there is always a `data/` sub-path between the mount point and
    # the secret actual path, eg. if your mount point is `secret/` (the default) and your secret
    # path is `my-api/prod`, the full path to use is `secret/data/my-api/prod`.
    # We don't pass a `vault_secret_key` here so that Pydantic-Vault fetches all fields at once.
    credentials: Credentials = Field(..., vault_secret_path="secret/data/my-api/prod")

settings = Settings()
settings.credentials.root_user  # "root"
settings.credentials.root_password.get_secret_value()  # "a_v3ry_s3cur3_p4ssw0rd"
```

### Retrieve a secret from a KV v1 secret engine

Suppose your secret is at `my-api/prod` and looks like this:
```
Key             Value
---             -----
root_user       root
root_password   a_v3ry_s3cur3_p4ssw0rd
```

Your settings class would be:
```python
class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a KV v1 secret engine, the secret path is directly appended to the mount point,
    # eg. if your mount point is `kv/` (the default) and your secret path is `my-api/prod`,
    # the full path to use is `kv/my-api/prod` (unlike with KV v2 secret engines).
    # The `vault_secret_key` is the specific key to extract from a secret.
    username: str = Field(..., vault_secret_path="kv/my-api/prod", vault_secret_key="root_user")
    password: SecretStr = Field(..., vault_secret_path="kv/my-api/prod", vault_secret_key="root_password")

settings = Settings()

settings.username  # "root"
settings.password.get_secret_value()  # "a_v3ry_s3cur3_p4ssw0rd"
```

⚠ Beware of the [known limitations](#known-limitations) on KV v1 secrets!

### Retrieve a secret from a database secret engine

Database secrets can be "dynamic", generated by Vault every time you request access.
Because every call to Vault will create a new database account, you cannot store the username
and password in two different fields in your settings class, or you would get the username of the
*first* generated account and the password of the *second* account. This means that you must *not*
pass a `vault_secret_key`, so that Pydantic-Vault retrieves the whole secret at once.

You can store the credentials in a dict or in a custom `BaseModel` class:
```python
class DbCredentials(BaseModel):
    username: str
    password: SecretStr


class Settings(BaseSettings):
    # The `vault_secret_path` is the full path (with mount point included) to the secret.
    # For a database secret engine, the secret path is `<mount point>/creds/<role name>`.
    # For example if your mount point is `database/` (the default) and your role name is
    # `my-db-prod`, the full path to use is `database/creds/my-db-prod`. You will receive
    # `username` and `password` fields in response.
    # You must *not* pass a `vault_secret_key` so that Pydantic-Vault fetches both fields at once.
    db_creds: DbCredentials = Field(..., vault_secret_path="database/creds/my-db-prod")
    db_creds_in_dict: dict = Field(..., vault_secret_path="database/creds/my-db-prod")

settings = Settings()

settings.db_creds.username  # "generated-username-1"
settings.db_creds.password.get_secret_value()  # "generated-password-for-username-1"
settings.db_creds_in_dict["username"]  # "generated-username-2"
settings.db_creds_in_dict["password"]  # "generated-password-for-username-2"
```

## Known limitations

- On KV v1 secret engines, if your secret has a `data` key and you do not specify a `vault_secret_key`
to load the whole secret at once, Pydantic-vault will only load the content of the `data` key.
  For example, with a secret `kv/my-secret`
  ```
  Key             Value
  ---             -----
  user            root
  password        a_v3ry_s3cur3_p4ssw0rd
  data            a very important piece of data
  ```
  and the settings class
  ```python
  class Settings(BaseSettings):
      my_secret: dict = Field(..., vault_secret_path="kv/my-secret")
  ```
  Pydantic-Vault will try to load only the `data` value (`a very important piece of data`) in
  `my_secret`, which will fail validation from Pydantic because it is not a dict.

  **Workaround:** Rename the `data` key in your secret 😅

  **Workaround:** Migrate to KV v2

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
[vault-auth-approle]: https://www.vaultproject.io/docs/auth/approle
[vault-auth-kubernetes]: https://www.vaultproject.io/docs/auth/kubernetes
[vault-auth-token]: https://www.vaultproject.io/docs/auth/token
[vault-kv-v2]: https://www.vaultproject.io/docs/secrets/kv/kv-v2/
