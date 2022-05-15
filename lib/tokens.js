/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import assert from 'assert-plus';
import {authenticator} from 'otplib';
import {checkAuthenticationRequirements} from './authenticationMethods.js';
import {
  fastHash,
  generateNonce,
  validateTokenType,
  verifySlowHashOrUnguessableChallenge
} from './helpers.js';
import {generateId} from 'bnid';
import {pbkdf2, deserializePhc} from './pbkdf2.js';
import {
  getAccountRecord, setToken, pushToken, removeToken
} from './tokenStorage.js';
import {logger} from './logger.js';
import {notify as _notify} from './notify.js';

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
 * @param {string} [options.hash] - The slow-hashed value to use when setting
 *   a password token type; it must be in PHC (password hash competition)
 *   string format.
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
 *   entryStyle to `human` will generate low count character numeric-only nonce
 *   and setting it to `machine` will generate a large, random, unguessable
 *   base58-encoded nonce.
 *
 * @returns {Promise<object>} - Returns a Promise that resolves once the
 *   operation completes with token details depending on the type.
 */
export async function set({
  accountId, email, type, clientId, serviceId,
  hash, authenticationMethod = type, requiredAuthenticationMethods = [],
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
        // only include `id`, `type`, and `challenge` information;
        // Note: `id` may be used in conjunction with `account`
        // or `email` in a deep link for authentication
        token: {
          id: result.id,
          type: result.type,
          challenge: result.challenge
        },
        notification: {type: 'create'}
      });
    } catch(error) {
      logger.error('Failed to notify user of token creation.', {
        account: accountId,
        email,
        type,
        error
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
 * @param {string} [options.id] - The id of the token to get.
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

  // get token(s) from account meta; will throw if no token found
  const record = await getAccountRecord({
    accountId, email, id, type, requireToken: true
  });

  const result = record.meta['bedrock-authn-token'].tokens[type];

  let token;
  if(Array.isArray(result)) {
    token = id ?
      result.find(token => token.id === id) :
      result[result.length - 1];
  } else {
    token = result;
  }

  // filter out token if expired
  if(filterExpiredTokens) {
    const now = new Date();
    if(token.expires < now) {
      // token expired, throw not found
      throw new BedrockError(
        'Authentication token has expired.',
        'NotFoundError', {
          httpStatusCode: 404,
          public: true
        });
    }
  }

  // add default `hashParameters` as needed (legacy bcrypt tokens have `salt`
  // property)
  if(type !== 'totp' && token.salt) {
    token = {
      ...token,
      hashParameters: {id: 'bcrypt', salt: token.salt, params: {r: 10}}
    };
  }

  return token;
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
  const allTokens = (Array.isArray(result) ? result : [result]).map(token => {
    // add default `hashParameters` as needed (legacy bcrypt tokens have `salt`
    // property)
    if(type !== 'totp' && !token.hashParameters) {
      token = {
        ...token,
        hashParameters: {id: 'bcrypt', salt: token.salt, params: {r: 10}}
      };
    }
    return token;
  });

  // filter tokens by expired status
  const tokens = [];
  const expiredTokens = [];
  const now = new Date();
  for(const token of allTokens) {
    // token.expires was a Date instance when it was inserted into MongoDB
    // and it is therefore a Date instance when it comes out which makes this
    // a valid comparison
    if(!token.expires || token.expires > now) {
      // auto-expire legacy bcrypt nonces
      if(type === 'nonce' && token.salt) {
        expiredTokens.push(token);
      } else {
        tokens.push(token);
      }
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
 * @param {string} [options.hash] - The slow hash (e.g., pbkdf2 or bcrypt) for
 *   or a password / human-entry style nonce; `bcrypt` is deprecated.
 * @param {string} [options.challenge] - The token challenge value for token
 *   types (e.g., `totp` or `nonce` with machine-entry style nonce) that do not
 *   hash token challenges.
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

  if(!(hash || challenge) || (hash && challenge)) {
    throw new Error('Exactly one of "hash" or "challenge" is required.');
  }

  if(type === 'totp' && hash) {
    // totp token values MUST NOT be hashed
    throw new BedrockError(
      'Authentication token challenge must not be hashed.', {
        name: 'DataError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  const slowHashOrUnguessableChallenge = hash ?? challenge;

  // get token from account meta
  const record = await getAccountRecord({
    accountId, email, type, requireToken: true
  });

  let token;
  if(type === 'nonce') {
    token = _getMatchingNonce(
      {record, clientId, slowHashOrUnguessableChallenge});
    if(!token) {
      // no matching nonce token, return early
      return false;
    }
  } else {
    token = record.meta['bedrock-authn-token'].tokens[type];
  }

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

  if(type === 'nonce') {
    // token already verified because that's how it was found above
    verified = true;
    // nonce now used; remove it
    try {
      await remove({account: record.account.id, type});
    } catch(e) {
      // only throw error if remove fails and token doesn't expire,
      // otherwise let it expire
      if(e.name !== 'NotFoundError' && !token.expires) {
        throw e;
      }
    }
  } else if(type === 'totp') {
    const cfg = config['authn-token'];
    const {window} = cfg.totp;
    // FIXME: create custom instance to just set these global options once
    authenticator.options = {window};
    // test the totpToken provided to the API against the secret drawn from
    // the accounts database
    verified = authenticator.verify({token: challenge, secret: token.secret});
  } else {
    // verify slow hash / unguessable challenge against fast hash value
    verified = verifySlowHashOrUnguessableChallenge(
      {clientId, slowHashOrUnguessableChallenge, sha256: token.sha256});
  }

  if(!verified) {
    return false;
  }

  // verified; return account ID, email, and token information
  return {
    id: record.account.id,
    email: record.account.email || null,
    token: {
      type,
      authenticationMethod: token.authenticationMethod || type
    }
  };
}

async function _initToken({
  authenticationMethod, requiredAuthenticationMethods
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
    // if length of tokens exceeds `maxCount`, throw `NotAllowed` error
    if(tokens.length >= maxCount) {
      throw new BedrockError(
        `No more than ${maxCount} tokens can be pending at once.`,
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

  // generate new challenge
  const challenge = await generateNonce(typeOptions);

  // if nonce challenge entry style is human, then we must use a slow hash
  // function to defend against brute force attacks; machine challenges are
  // sufficiently large and random to be unguessable
  let slowHashOrUnguessableChallenge;
  if(typeOptions.entryStyle === 'human') {
    // reuse hash params from the last token that has them, provided that they
    // are up to date with the system configuration
    let hashParameters;
    for(let i = tokens.length - 1; i >= 0; --i) {
      const token = tokens[i];
      if(token?.hashParameters?.id === cfg.pbkdf2.id &&
        token?.hashParameters?.params?.i === cfg.pbkdf2.iterations) {
        hashParameters = token.hashParameters;
        break;
      }
    }

    if(!hashParameters) {
      // generate new hash parameters
      hashParameters = {
        id: cfg.pbkdf2.id,
        params: {i: cfg.pbkdf2.iterations}
      };
    }

    // hash challenge
    const {hash, phc} = await pbkdf2({
      iterations: hashParameters.params.i,
      secret: challenge,
      salt: hashParameters.params.salt,
      saltSize: cfg.pbkdf2.saltSize
    });
    if(!hashParameters.salt) {
      hashParameters.salt = phc.salt;
    }
    token.hashParameters = hashParameters;
    slowHashOrUnguessableChallenge = hash;
  } else {
    // challenge is an unguessable, large, random number; do not hash
    slowHashOrUnguessableChallenge = challenge;
  }

  // fast hash client ID and slow hash / challenge combination for storage
  token.sha256 = fastHash({clientId, slowHashOrUnguessableChallenge});
  token.expires = new Date(Date.now() + ttl);

  await _pushNonceToken({accountId, email, token});

  // include `challenge` in return value so it can, for example, be sent to
  // a user via some communication mechanism (e.g., email)
  return {challenge};
}

async function _addPasswordToken({accountId, email, token, hash}) {
  assert.string(hash, 'hash');

  // try to deserialize `hash` into PHC object
  const phc = deserializePhc({hash});

  // enforce minimum number of iterations
  const {minIterations} = config['authn-token'].pbkdf2;
  if(phc.params.i < minIterations) {
    throw new BedrockError(
      `Iteration count (${phc.params.i}) must be at least ${minIterations}.`, {
        name: 'ConstraintError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  // only include `id`, `params`, and `salt` from parsed PHC object; the hash
  // value is to be hashed again with a fast hash below for more secure storage
  const {id, params, salt} = phc;
  token.hashParameters = {id, params, salt};
  token.sha256 = fastHash({slowHashOrUnguessableChallenge: hash});
  await setToken({accountId, email, type: 'password', token});
}

async function _addTotpToken({accountId, email, token, serviceId}) {
  // get the account record to both get the account email and to check whether
  // another `totp` token is already set
  const record = await getAccountRecord({
    accountId, email, type: 'totp', requireToken: false
  });

  // ensure no existing totp secret is set
  const exists = !!record.meta?.['bedrock-authn-token']?.tokens?.totp;
  if(exists) {
    throw new BedrockError(
      'TOTP authentication token already set.', 'DuplicateError', {
        httpStatusCode: 409,
        public: true
      });
  }

  // set email for use in label/url
  if(record.account.email) {
    email = record.account.email;
  }

  // presently, other params are not saved in the token, only the `secret` is;
  // this could be potentially changed in the future to store the params with
  // the token as well to allow for change
  token.secret = authenticator.generateSecret();

  // defaults
  const allOptions = authenticator.allOptions();

  // prepare TOTP params
  const params = {
    // algorithm, digits, period are defaults for otplib 'authenticator'
    // note: secret is also included in `otpAuthUrl`
    secret: token.secret,
    label: email || accountId,
    // a service name, `undefined` is OK if `serviceId` was not passed in
    service: serviceId,
    // note: these could be made configurable instead -- and potentially stored
    // with the token in case they change
    algorithm: allOptions.algorithm.toUpperCase(),
    digits: allOptions.digits,
    step: allOptions.step
  };
  // produces a URL like `otpauth://totp/...`
  params.otpAuthUrl = authenticator.keyuri(
    params.label, params.service, params.secret);

  await setToken({accountId, email, type: 'totp', token});

  return params;
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
    result = _addNonceToken({accountId, email, token, clientId, typeOptions});
  } else if(type === 'password') {
    result = _addPasswordToken({accountId, email, token, hash});
  } else if(type === 'totp') {
    result = _addTotpToken({accountId, email, token, serviceId});
  }

  return {id: token.id, type, ...await result};
}

function _getMatchingNonce({
  record, clientId, slowHashOrUnguessableChallenge
}) {
  const tokens = record.meta['bedrock-authn-token'].tokens.nonce;
  const now = new Date();
  for(const token of tokens) {
    if(!verifySlowHashOrUnguessableChallenge(
      {clientId, slowHashOrUnguessableChallenge, sha256: token.sha256})) {
      continue;
    }
    if(token.expires && now >= token.expires) {
      throw new BedrockError(
        'Authentication token has expired.',
        'NotFoundError', {
          httpStatusCode: 404,
          public: true
        });
    }
    return token;
  }
}
