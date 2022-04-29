# bedrock-authn-token ChangeLog

## 9.0.0 - 2022-04-xx

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
