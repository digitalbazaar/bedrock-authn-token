/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';
import assert from 'assert-plus';
import {authenticator} from 'otplib';
import bcrypt from 'bcrypt';
import {checkAuthenticationRequirements} from './authenticationMethods.js';
import {
  combinedHash,
  generateNonce,
  getBcryptSalt,
  prefixedHash,
  validateBcryptHash,
  validateTokenType,
  verifyHash
} from './helpers.js';
import {createRequire} from 'module';
import {
  getAccountRecord, setToken, pushToken, removeToken
} from './tokenStorage.js';
import {logger} from './logger.js';
import {notify as _notify} from './notify.js';
const require = createRequire(import.meta.url);
const {generateId} = require('bnid');

const {config, util: {BedrockError}} = bedrock;

/**
 * Sets a token for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} [options.accountId] - The ID of the account to set a token
 *   for.
 * @param {string} [options.email] - The email of the account to set a token
 *   for.
 * @param {string} options.type - The type of token to set (`password`,
 *   `nonce`, or `totp`).
 * @param {string} [options.clientId] - An identifier for the client to bind a
 *   token to, if supported by the token type.
 *  @param {string} [options.serviceId] - An identifier to associate with the
 *   token. For TOTP tokens, `serviceId` is encoded in the `otpAuthUrl` value
 *   returned by this API.
 * @param {string} [options.hash] - The hashed value to use to set a
 *   password/nonce or other type of token that uses hashed token values.
 * @param {string} [options.authenticationMethod=type] - An optional,
 *   application specific authentication method identifier to assign to this
 *   token, useful for multifactor flows to create dependencies on different
 *   types or instances of tokens.
 * @param {Array} [options.requiredAuthenticationMethods=[]] - An optional,
 *   application specific set of authentication methods (specified by ID) that
 *   must first be satisfied before this token can be verified.
 * @param {boolean} [options.notify=true] - Set to `true` to notify the account
 *   user, `false` not to.
 * @param {string} [options.typeOptions={entryStyle: 'human'}] - Setting
 *   entryStyle to `human` will generate 9 character numeric-only nonce and
 *   setting it to `machine` will generate base58 encoded nonce.
 *
 * @returns {Promise<object>} - Returns a Promise that resolves once the
 *   operation completes with token details depending on the type.
 */
export async function set({
  accountId, email, type, clientId, serviceId, hash,
  authenticationMethod = type, requiredAuthenticationMethods = [],
  notify = true, typeOptions = {entryStyle: 'human'}
} = {}) {
  assert.optionalString(accountId, 'accountId');
  assert.optionalString(email, 'email');
  assert.optionalString(clientId, 'clientId');
  assert.optionalString(serviceId, 'serviceId');
  if(!(accountId || email) || (accountId && email)) {
    throw new Error('Exactly one of "accountId" or "email" is required.');
  }
  validateTokenType(type);

  // `accountId` must be set for types other than `nonce`
  if(type !== 'nonce') {
    assert.string(accountId, 'accountId');
  }

  const result = await _createToken({
    accountId, email, type,
    authenticationMethod, requiredAuthenticationMethods,
    hash, clientId, serviceId, typeOptions
  });

  if(notify) {
    try {
      await _notify({
        accountId, email, authenticationMethod,
        // do not include hash, salt, or other properties for verify
        // Note: however, `id` may be used in conjunction with `account`
        // or `email` in a deep link for authentication
        token: {
          id: result.id,
          type: result.type,
          challenge: result.challenge
        },
        notification: {type: 'create'}
      });
    } catch(e) {
      logger.error('Failed to notify user of token creation.', {
        account: accountId,
        email,
        type,
        error: e
      });
    }
  }

  return result;
}

/**
 * Gets a token for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} [options.accountId] - The ID of the account.
 * @param {string} [options.email] - The email of the account.
 * @param {string} options.type - The type of token to get (`password`,
 *   `nonce`, or `totp`).
 * @param {string} options.id - The id of the token to get.
 * @param {boolean} [options.filterExpiredTokens] - Set to `true` to drop
 *   expired token and to `false` to get token even if it is expired.
 *
 * @returns {Promise<object>} - Returns a Promise that resolves to the token.
 */
export async function get({
  accountId, email, type, id, filterExpiredTokens = true
} = {}) {
  assert.optionalString(accountId, 'accountId');
  assert.optionalString(email, 'email');
  assert.optionalString(id, 'id');
  assert.optionalBool(filterExpiredTokens, 'filterExpiredTokens');
  if(!(accountId || email)) {
    throw new Error('Either "accountId" or "email" is required.');
  }
  validateTokenType(type);

  // get token from account meta
  const record = await getAccountRecord({
    accountId, email, id, type, requireToken: true
  });

  let result = record.meta['bedrock-authn-token'].tokens[type];
  let rValue;
  if(type === 'nonce') {
    if(id) {
      result = result.filter(token => token.id === id);
    }
    rValue = result[result.length - 1];
  } else {
    rValue = result;
  }
  // filter expired token
  if(filterExpiredTokens) {
    const now = new Date();
    if(rValue.expires < now) {
      // token expired, express as not found
      throw new BedrockError(
        'Authentication token has expired.',
        'NotFoundError', {
          httpStatusCode: 404,
          public: true
        });
    }
  }
  return rValue;
}

/**
 * Gets tokens for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} [options.accountId] - The ID of the account.
 * @param {string} [options.email] - The email of the account.
 * @param {string} options.type - The type of tokens to get (`password`,
 *   `nonce`, or `totp`).
 *
 * @returns {Promise<Array>} - Return a Promise that resolves to tokens.
 */
export async function getAll({accountId, email, type} = {}) {
  assert.optionalString(accountId, 'accountId');
  assert.optionalString(email, 'email');
  if(!(accountId || email)) {
    throw new Error('Either "accountId" or "email" is required.');
  }
  validateTokenType(type);

  // get tokens from account meta
  const record = await getAccountRecord({
    accountId, email, type, requireToken: false
  });

  // check if any of the keys are undefined or null
  const result = record.meta?.['bedrock-authn-token']?.tokens?.[type] ?? [];
  const allTokens = Array.isArray(result) ? result : [result];
  const tokens = [];
  const expiredTokens = [];
  const now = new Date();
  for(const token of allTokens) {
    // token.expires was a Date instance when it was inserted into MongoDB
    // and it is therefore a Date instance when it comes out which makes this
    // a valid comparison
    if(!token.expires || token.expires > now) {
      tokens.push(token);
    } else {
      expiredTokens.push(token);
    }
  }
  return {allTokens, tokens, expiredTokens};
}

/**
 * Removes a token from an account.
 *
 * @param {object} options - The options to use.
 * @param {string} options.accountId - The ID of the account to remove a token
 *   from.
 * @param {string} options.type - The type of token to remove (`password`,
 *   `nonce`, or `totp`).
 * @param {string} [options.id] - The id of the token to be removed.
 *
 * @returns {Promise} - Returns a Promise that resolves once the operation
 *   completes.
 */
export async function remove({accountId, type, id} = {}) {
  assert.string(accountId, 'accountId');
  assert.optionalString(id, 'id');
  validateTokenType(type);
  return removeToken({accountId, type, id});
}

/**
 * Verifies a token for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} [options.accountId] - The ID of the account to verify a
 *   token for.
 * @param {string} [options.clientId] - An identifier for the client to bind a
 *   token to, if supported by the token type.
 * @param {string} [options.email] - The email of the account to verify a token
 *   for.
 * @param {string} options.type - The type of token to verify (`password`,
 *   `nonce`, `totp`).
 * @param {string} [options.hash] - The bcrypt hash to verify for a
 *   password/nonce or other type of token that uses hashed token challenges.
 * @param {string} [options.challenge] - The token challenge value for token
 *   types that do not hash token challenges.
 * @param {Array} [options.authenticatedMethods=[]] - A list of identifiers for
 *   other methods methods that have already been authenticated (useful for
 *   multifactor verification where one method depends on other methods to
 *   first be used).
 *
 * @returns {Promise<object>} - Returns a Promise that resolves to an object
 *   containing the account ID, the account `email`, and token information if
 *   verified; `false` if not.
 */
export async function verify({
  accountId, email, type, hash, challenge, clientId, authenticatedMethods = []
} = {}) {
  assert.optionalString(accountId, 'account');
  assert.optionalString(clientId, 'clientId');
  assert.optionalString(email, 'email');
  assert.optionalArrayOfString(authenticatedMethods, 'authenticatedMethods');
  if(!(accountId || email)) {
    throw new Error('Either "accountId" or "email" is required.');
  }
  validateTokenType(type);
  assert.optionalString(hash, 'hash');
  assert.optionalString(challenge, 'challenge');

  if(hash) {
    // FIXME: use pbkdf2 instead
    validateBcryptHash(hash);
  } else if(!challenge) {
    throw new Error('Either "hash" or "challenge" is required.');
  } else if(type !== 'totp') {
    // non-totp token values MUST be hashed
    throw new BedrockError(
      'Authentication token challenge must be hashed.', 'DataError', {
        httpStatusCode: 400,
        public: true
      });
  }

  // get token from account meta
  const record = await getAccountRecord({
    accountId, email, type, requireToken: true
  });

  let nonceVerified;
  let tokenValue = record.meta['bedrock-authn-token'].tokens[type];
  const now = new Date();
  if(type === 'nonce') {
    for(const token of tokenValue) {
      nonceVerified = verifyHash({clientId, hash, sha256: token.sha256});
      if(nonceVerified) {
        if(token.expires && now >= token.expires) {
          throw new BedrockError(
            'Authentication token has expired.',
            'NotFoundError', {
              httpStatusCode: 404,
              public: true
            });
        }
        tokenValue = token;
        break;
      }
    }
    if(!nonceVerified) {
      // no token matches the given `hash` and `clientId`, so not verified
      return false;
    }
    // check for other token type expiration if needed.
  }

  const token = tokenValue;
  // check that dependencies have been met ... other authentication methods
  // that must have already been used (for multifactor flows)
  const {requiredAuthenticationMethods} = token;
  if(requiredAuthenticationMethods) {
    const met = await checkAuthenticationRequirements({
      requiredAuthenticationMethods,
      authenticatedMethods
    });
    if(!met) {
      throw new BedrockError(
        'Authentication token dependencies not met; other authentication ' +
        'methods must be used before verifying this token.',
        'NotAllowedError', {
          httpStatusCode: 400,
          public: true
        });
    }
  }

  let verified = false;

  if(type === 'totp') {
    const cfg = config['authn-token'];
    const {window} = cfg.totp;
    // FIXME: create custom instance to just set these global options once
    authenticator.options = {window};
    // test the totpToken provided to the API against the secret drawn from
    // the accounts database
    verified = authenticator.verify({token: challenge, secret: token.secret});
  } else {
    // `type` is either `password` or `nonce`, which must be hashed
    if(!hash) {
      throw new BedrockError(
        'Authentication token challenge must be hashed.', 'DataError', {
          httpStatusCode: 400,
          public: true
        });
    }
    if(type === 'nonce') {
      verified = nonceVerified;
    } else {
      // verify hash-based token value
      verified = verifyHash({clientId, hash, sha256: token.sha256});
    }
  }

  if(verified) {
    // `nonce` verified, remove it
    if(type === 'nonce') {
      try {
        await remove({account: record.account.id, type});
      } catch(e) {
        // only throw error if remove fails and token doesn't expire,
        // otherwise let it expire
        if(e.name !== 'NotFoundError' && !token.expires) {
          throw e;
        }
      }
    }
    // return account ID, email, and token information
    return {
      id: record.account.id,
      email: record.account.email || null,
      token: {
        type,
        authenticationMethod: token.authenticationMethod || type
      }
    };
  }
  return false;
}

async function _initToken({
  authenticationMethod, requiredAuthenticationMethods, type
}) {
  const token = {
    // generate 128-bit random ID for token, sufficiently large to avoid
    // conflict
    id: await generateId({fixedLength: true}),
    authenticationMethod,
    requiredAuthenticationMethods
  };
  return token;
}

async function _pushNonceToken({accountId, email, token}) {
  const {maxNonceCount: maxCount} = config['authn-token'].nonce;
  const type = 'nonce';

  // keep trying to push nonce token until success or error
  while(true) {
    if(await pushToken({accountId, email, type, token, maxCount})) {
      break;
    }

    // if new nonce token was not pushed, then either the account doesn't
    // exist or there were too many nonces at the time

    // check if too many nonces exist...
    const {tokens} = await getAll({accountId, email, type});

    // FIXME: may need to allow up to N tokens, one per `clientId` if
    // `clientId` is set
    // if length of tokens exceeds `maxNonceCount`, throw `NotAllowed` error
    if(tokens.length >= maxNonceCount) {
      throw new BedrockError(
        `No more than ${maxNonceCount} tokens can be pending at once.`,
        'NotAllowedError', {
          httpStatusCode: 400,
          public: true
        });
    }

    // loop to try again...
  }
}

async function _addNonceToken({
  accountId, email, token, clientId, typeOptions
}) {
  const cfg = config['authn-token'];
  const {defaults: {ttl}, maxNonceCount} = cfg.nonce;

  // check if nonce exists
  const {tokens} = await getAll({accountId, email, type: 'nonce'});

  // FIXME: may need to allow up to N tokens, one per `clientId` if
  // `clientId` is set
  // if length of tokens exceeds `maxNonceCount`, throw `NotAllowed` error
  if(tokens.length >= maxNonceCount) {
    throw new BedrockError(
      `No more than ${maxNonceCount} tokens can be pending at once.`,
      'NotAllowedError', {
        httpStatusCode: 400,
        public: true
      });
  }

  // check for existing salt and parse rounds
  let lastTokenSalt;
  let parsedRounds;
  if(tokens.length > 0) {
    lastTokenSalt = tokens[tokens.length - 1].salt;
    parsedRounds = parseInt(lastTokenSalt.split('$')[2]);
  }

  // only generate new salt if rounds do not match (which
  // also happens when there was no previous salt); reuse of
  // the last salt enables other unexpired tokens to be used
  // for authentication
  let salt;
  if(parsedRounds === cfg.bcrypt.rounds) {
    salt = lastTokenSalt;
  } else {
    salt = await bcrypt.genSalt(cfg.bcrypt.rounds);
  }

  // generate new challenge
  const challenge = await generateNonce(typeOptions);
  const hash = await bcrypt.hash(challenge, salt);
  token.salt = salt;
  token.sha256 = combinedHash({clientId, hash});
  token.expires = new Date(Date.now() + ttl);

  await _pushNonceToken({accountId, email, token});

  // include `challenge` in return value so it can, for example, be sent to
  // a user via some communication mechanism (e.g., email)
  return {challenge};
}

async function _addPasswordToken({accountId, email, token, hash}) {
  assert.string(hash, 'hash');
  validateBcryptHash(hash);
  token.salt = getBcryptSalt(hash);
  token.sha256 = prefixedHash(hash);
 await setToken({accountId, email, type: 'password', token});
}

async function _addTotpToken({accountId, email, token, serviceId}) {
  // FIXME: don't get token twice, just get account and check for token
  // presence...

  // ensure no existing totp secret is set
  try {
    await get({accountId, type: 'totp'});
    // `NotFoundError` not thrown so a totp secret is already set
    throw new BedrockError(
      'TOTP authentication token already set.', 'DuplicateError', {
        httpStatusCode: 409,
        public: true
      });
  } catch(e) {
    if(e.name !== 'NotFoundError') {
      throw e;
    }
  }

  // get email for use in label/url
  const record = await brAccount.get({id: accountId});
  if(record.account.email) {
    email = record.account.email;
  }

  // FIXME: save params in token and use explicitly?
  // (algorithm, digits, step)
  token.secret = authenticator.generateSecret();

  // defaults
  const allOptions = authenticator.allOptions();

  // FIXME: clean up
  let rValue = {};

  // return TOTP params
  // algorithm, digits, period are defaults for otplib 'authenticator'
  rValue.secret = token.secret;
  // FIXME: use readable email and service name
  rValue.label = email || accountId;
  // a service name, `undefined` is OK if `serviceId` was not passed in
  rValue.service = serviceId;
  // TODO: make these bedrock.config options
  rValue.algorithm = allOptions.algorithm.toUpperCase();
  rValue.digits = allOptions.digits;
  rValue.step = allOptions.step;
  // produces a URL like `otpauth://totp/...`
  rValue.otpAuthUrl = authenticator.keyuri(
    rValue.label, rValue.service, rValue.secret);

  await setToken({accountId, email, type: 'totp', token});

  return rValue;
}

async function _createToken({
  accountId, email, type,
  authenticationMethod, requiredAuthenticationMethods,
  hash, clientId, serviceId, typeOptions
}) {
  const token = await _initToken(
    {authenticationMethod, requiredAuthenticationMethods});

  let result;
  if(type === 'nonce') {
    result = _addNonceToken(
      {accountId, email, token, clientId, typeOptions});
  }
  else if(type === 'password') {
    result = _addPasswordToken({accountId, email, token, hash});
  } else if(type === 'totp') {
    result = _addTotpToken({accountId, email, token, serviceId});
  }

  return {id: token.id, type: type, ...await result};
}
