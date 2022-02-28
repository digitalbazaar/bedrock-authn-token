# bedrock-authn-token ChangeLog

## 5.0.0 - 2022-02-28

### Changed
- **BREAKING**: Update length of `nonce` in `generateNonce` to 6 instead of 9.
  Additional care must be taken in deployments to prevent too many attempts to
  input (or "guess") a nonce at any verification endpoints in a short period of time.

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
