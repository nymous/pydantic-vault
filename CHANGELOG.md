# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Log discovered configuration to help debugging, see the "Logging" section in the Readme

### Changed
- Bump minimum `hvac` version to 0.10.6 instead of 0.10.0, to actually support AppRole authentication, and support the recently released 0.11.0


## [0.6.0b0] - 2021-07-16
First beta release! 🎉 Beware of the breaking changes listed below!

### Added
- Support any secret engine, not just KV v2 (#11)
- Support loading a whole secret at once as a dict if you don't specify the `vault_secret_key`
- Add examples for KV v1, KV v2 and Database secret engines
- Add test coverage

### Changed
- **BREAKING**: Require explicit full secret path (#11)
  This enables support for all secret engines instead of just KV v2, and allows you to use different secret engines in the same settings class.
  To migrate, add `secret/data/` in front of all your `vault_secret_path` (replace `secret/` with your KV v2 mount point), and remove the now unused `vault_secret_mount_point` config. For example:
  ```python
  # Before
  class Settings(BaseSettings):
      db_username = Field(..., vault_secret_path="my-api/prod", vault_secret_key="db_username")

      class Config:
          vault_secret_mount_point: str = "secret"

  # After
    class Settings(BaseSettings):
      db_username = Field(..., vault_secret_path="secret/data/my-api/prod", vault_secret_key="db_username")
  ```
  See the examples in the readme for more information.
- **BREAKING**: Invert the priority of environment variables and Config values (config now overrides what is set in environment variables)



## [0.5.0a0] - 2021-06-28
### Added
- Support Kubernetes authentication method (#10)
- Support custom mount point for authentication methods (#10)


## [0.4.1a1] - 2021-06-21
*This is a rerelease of 0.4.1a0 after some issues during deployment*

### Fixed
- Allow Pydantic to use default values if secret is not found in Vault (#9)


## [0.4.1a0] - 2021-06-21 [YANKED]
This release has been YANKED because of a bad deployment

### Fixed
- Allow Pydantic to use default values if secret is not found in Vault (#9)


## [0.4.0a0] - 2021-04-11
### Added
- Support Approle authentication


## [0.3.0a0] - 2021-04-06
### Added
- Get Vault address, namespace & token from environment variables
- Get Vault token from `~/.vault-token` file

### Fixed
- Fix crash when a Settings field did not use `vault_secret_path`/`vault_secret_key`


## [0.2.0a0] - 2021-03-14
### Changed
- Use the newly supported way of customizing settings sources, available since Pydantic 1.8


## [0.1.0a0] - 2021-03-21
### Added
- First alpha release

[Unreleased]: https://github.com/nymous/pydantic-vault/compare/0.6.0b0...HEAD
[0.6.0b0]: https://github.com/nymous/pydantic-vault/compare/0.5.0a0...0.6.0b0
[0.5.0a0]: https://github.com/nymous/pydantic-vault/compare/0.4.1a1...0.5.0a0
[0.4.1a1]: https://github.com/nymous/pydantic-vault/compare/0.4.1a0...0.4.1a1
[0.4.1a0]: https://github.com/nymous/pydantic-vault/compare/0.4.0a0...0.4.1a0
[0.4.0a0]: https://github.com/nymous/pydantic-vault/compare/0.3.0a0...0.4.0a0
[0.3.0a0]: https://github.com/nymous/pydantic-vault/compare/0.2.0a0...0.3.0a0
[0.2.0a0]: https://github.com/nymous/pydantic-vault/compare/0.1.0a0...0.2.0a0
[0.1.0a0]: https://github.com/nymous/pydantic-vault/releases/tag/0.1.0a0

