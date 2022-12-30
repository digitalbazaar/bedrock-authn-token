# bedrock-authn-token ChangeLog

## 10.4.0 - 2022-12-dd

### Changed
- Change internal use of `update` API for modifying accounts to
  use replacement vs. `patch` API. This change should have no
  impact on the API and should ease the transition to a new
  `@bedrock/account` version that no longer supports the `patch`
  API.

## 10.3.1 - 2022-12-11

### Fixed
- Ensure account ID is passed to update when updating clients.

## 10.3.0 - 2022-12-11

### Changed
- Require `@bedrock/account@8.2` to get latest update API features.
- Use `@bedrock/account` APIs internally to reduce possibility for
  breakage if the internals of `@bedrock/account` change.

### Removed
- Non-breaking removal of internal `explain` flags from APIs that
  were directly accessing `@bedrock/account` database collections.
- Non-breaking removal of peer dependency on `@bedrock/mongodb` because
  the database is no longer directly accessed.

## 10.2.0 - 2022-05-28

### Added
- Allow default `requiredAuthenticationMethods` to be configured via a new
  bedrock configuration option `defaultRequiredAuthenticationMethods`. If
  a non-empty array of strings is set as the config option value, then new
  accounts that do not have any `requiredAuthenticationMethods` set will
  receive the value. This feature is backwards compatible and makes no
  changes by default. It enables applications to avoid having to make an
  extra call during account registration to setup default required
  authentication methods.

## 10.1.0 - 2022-05-22

### Changed
- Replace `otplib` with `@digitalbazaar/totp`.

## 10.0.2 - 2022-05-21

### Fixed
- Fix salt reuse.

## 10.0.1 - 2022-05-21

### Fixed
- Fix bugs with token expiration code for legacy bcrypt tokens.

## 10.0.0 - 2022-05-21

### Changed
- **BREAKING**: Include `hashParameters` in password and nonce tokens. This
  change should be a mostly backwards compatible change but is marked breaking
  because it is a data structure change. However, if a password token does not
  have a `hashParameters` property, it is assumed to be `bcrypt` and is
  internally modified to add matching `hashParameters` before being returned.
  If a nonce token does not have a `hashParameters` property, it is
  auto-expired. Password / nonce hashing must be performed on the client, so
  the hash parameters are new information to be sent to the client so it can
  produce a matching hash.
- **BREAKING**: If client registration was used in an application previously,
  clients will need to re-register because prefixed hashes are no longer used
  internally (to eliminate unnecessary complexity).
- **BREAKING**: Store fast hashes of token values as binary data instead of
  as base64 strings. This change should not require any database migration and
  the code handles old values retrieved from the database that are strings.
- **BREAKING**: Machine-entry style nonces are no longer slow hashed because it
  is unnecessary complexity that does not add security. Nonces generated this
  way and entered this way should be submitted as `challenge` to be verified,
  not `hash`.
- Use of prefixed hashes is now deprecated and its configuration option
  (`hashPrefix`) will be removed in a future version. It is an unnecessary
  complexity that does not add security (given the other design choices).

### Removed
- **BREAKING**: Remove database `explain` option from most public APIs.
- **BREAKING**: Remove `challenge` `type`. This type was never implemented and
  can be confused with the option `challenge` which specifies an unhashed
  value to be provided when verifying a `totp` token.
- **BREAKING**: Remove `bcrypt` from configuration and as an
  internally-used slow hash function. Use `pbkdf2` instead because it is
  widely available in clients, especially web browsers -- which is where
  most slow hashing occurs given the current design.

## 9.0.0 - 2022-04-29

### Changed
- **BREAKING**: Update peer deps:
  - `@bedrock/core@6`
  - `@bedrock/account@8`
  - `@bedrock/mongodb@10`.

## 8.0.0 - 2022-04-06

### Changed
- **BREAKING**: Rename package to `@bedrock/authn-token`.
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Remove default export.
- **BREAKING**: Require node 14.x.

## 7.1.1 - 2022-03-26

### Fixed
- Ensure module uses a default export for backwards compatibility.

## 7.1.0 - 2022-03-24

### Changed
- Update peer deps:
  - `bedrock@4.5`
  - `bedrock-mongodb@8.5`.
- Update internals to use esm style and use `esm.js` to
  transpile to CommonJS.

## 7.0.0 - 2022-03-08

### Changed
- **BREAKING**: Use `bedrock-account@6` which removes `bedrock-permission`
  including concepts such as `actor`.
- **BREAKING**: Updated peer dependencies, use:
  - `bedrock-account@6.1`
  - `bedrock-mongodb@8.4`
  - Remove `bedrock-permission`.
- **BREAKING**: Rename `account` param to `accountId` in all functions where
  its value is an ID for the account.
- **BREAKING**: Move `maxNonceCount` out of `defaults` namespace since it is
  not a "default" that can be overridden via an API call.

### Removed
- **BREAKING**: Remove all usage of `bedrock-permission` including
  roles (e.g., `sysResourceRole`), `actor`, etc. All authz should
  be managed via HTTP (or other) APIs and technologies such as
  zcaps, meters, and oauth2.

## 6.0.0 - 2022-03-02

### Changed
- **BREAKING**: Remove `catch` around `api.getAll` for tokens, allow
  `NotFoundError` to be thrown if an account is not found.

## 5.0.0 - 2022-02-28

### Changed
- **BREAKING**: Update length of `nonce` in `generateNonce` to 6 instead of 9.
  Additional care must be taken in deployments to prevent too many attempts to
  input (or "guess") a nonce at any verification endpoints in a short period of
  time.

## 4.1.0 - 2021-11-09

### Added
- Added optional `explain` param to get more details about database performance.
- Added database tests in order to check database performance.

## 4.0.1 - 2021-10-08

### Fixed
- Fix issue with salt mismatch when multiple tokens are generated.

## 4.0.0 - 2021-05-04

### Changed
- **BREAKING**: Updated `getAll` function to now return an object of
  `allTokens`, `tokens`, and `expiredTokens`.
- **BREAKING**: Updated `set` API to use the updated object from the `getAll`
  API request.
- Updated tests to reflect the latest code changes.

## 3.0.0 - 2021-01-13

### Added
- **BREAKING**: Modifiy `set` api and `generateNonce` function to take
  `typeOptions` param.
- `get` and `getAll` api can take an optional `filterExpiredTokens` param
  which can drop expired tokens if set to `true`.
- `remove` api can take an optional `id` param of a token to be removed.
- Added tests.

### Changed
- **BREAKING**: `nonce` type tokens have a `maxCount` of 5, with 10 minute
  expiration for each.
- Updated test deps to use bedrock-account@5.
- Updated peerDeps to use bedrock-mongodb@8.1.1.

## 2.2.1 - 2020-07-07

### Fixed
- Fix usage of the MongoDB projection API.

## 2.2.0 - 2020-06-29

### Changed
- Use bedrock-account@4.
- Update test deps.

## 2.1.0 - 2020-06-18

### Changed
- Use bcrypt@5.

## 2.0.0 - 2020-06-09

### Changed
- **BREAKING**: Use mongo driver 3.5 api.
- **BREAKING**: Upgrade bedrock-mongodb to ^7.0.0.
- **BREAKING**: Use upgraded versions of `bedrock-account`, `bedrock-identity`,
  & `bedrock-permission`.

## 1.4.0 - 2020-04-09

### Changed
- Use bcrypt@4 that includes pre-built binaries for Node.js 12.

## 1.3.0 - 2020-03-05

### Added
- `totp.window` config option to increase time step window. Default to accept
  codes 1 time step in past and future.

## 1.2.0 - 2020-03-04

### Added
- Support for TOTP tokens.

## 1.1.1 - 2020-01-24

### Fixed
- Fix dependency typo.

## 1.1.0 - 2020-01-06

### Added
- Add option for including `clientId` in `nonce` and `challenge` tokens.

## 1.0.0 - 2019-12-24

### Added
- Added core files.

- See git history for changes.
