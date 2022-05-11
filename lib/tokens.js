/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';
import * as database from '@bedrock/mongodb';
import assert from 'assert-plus';
import {authenticator} from 'otplib';
import bcrypt from 'bcrypt';
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
import jsonpatch from 'fast-json-patch';
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
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<object> | ExplainObject} - Returns a Promise that resolves
 *   once the operation completes with optional token details depending on the
 *   type or returns an ExplainObject if `explain=true`.
 */
export async function set({
  accountId, email, type, clientId, serviceId, hash,
  authenticationMethod = type, requiredAuthenticationMethods = [],
  notify = true, typeOptions = {entryStyle: 'human'}, explain = false
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

  const token = {
    authenticationMethod,
    requiredAuthenticationMethods
  };

  // generate 128-bit random ID for token, sufficiently large to avoid conflict
  token.id = await generateId({fixedLength: true});

  const rValue = {type, id: token.id};
  let challenge;

  let allTokens;
  let tokens;
  if(type === 'password') {
    assert.string(hash, 'hash');
    validateBcryptHash(hash);
    token.salt = getBcryptSalt(hash);
    token.sha256 = prefixedHash(hash);
  } else if(type === 'nonce') {
    const cfg = config['authn-token'];
    const {defaults: {ttl}, maxNonceCount} = cfg.nonce;

    // check if nonce exists
    ({allTokens, tokens} = await getAll({accountId, email, type}));

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

    // generate new token
    challenge = await generateNonce(typeOptions);
    const hash = await bcrypt.hash(challenge, salt);
    token.salt = salt;
    token.sha256 = combinedHash({clientId, hash});
    token.expires = new Date(Date.now() + ttl);

    // return challenge
    rValue.challenge = challenge;
  } else if(type === 'totp') {
    // ensure no existing totp secret is set
    try {
      await get({accountId, type});
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
  }

  // add token to meta
  const query = {};
  if(accountId) {
    query.id = database.hash(accountId);
  } else {
    query['account.email'] = email;
  }

  let tokenTypeValue;
  if(type === 'nonce') {
    // include old value in the query to ensure that no concurrent
    // changes occurred via another process
    const oldValue = allTokens.length > 0 ?
      allTokens.slice() : {$in: [null, []]};
    query['meta.bedrock-authn-token.tokens.nonce'] = oldValue;
    tokens.push(token);
    tokenTypeValue = tokens;
  } else {
    tokenTypeValue = token;
  }

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  const result = await database.collections.account.updateOne(
    query, {
      $set: {
        [`meta.bedrock-authn-token.tokens.${type}`]: tokenTypeValue
      }
    }, database.writeOptions);
  if(result.result.n === 0) {
    if(type === 'nonce') {
      throw new BedrockError(
        'Could not set account "nonce" token; another token ' +
        'was set concurrently.',
        'InvalidStateError', {httpStatusCode: 409, public: true});
    }
    throw new BedrockError(
      'Could not set account token. Account not found.',
      'NotFoundError', {httpStatusCode: 404, public: true});
  }

  if(notify) {
    try {
      await _notify({
        accountId, email, authenticationMethod,
        // do not include hash, salt, or other properties for verify
        // Note: however, `id` may be used in conjunction with `account`
        // or `email` in a deep link for authentication
        token: {id: token.id, type, challenge},
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

  return rValue;
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
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<object> | ExplainObject} - Returns a Promise that resolves
 *   to the token or an ExplainObject if `explain=true`.
 */
export async function get({
  accountId, email, type, id, filterExpiredTokens = true, explain = false
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
  const record = await _getAccountRecord({
    accountId, email, id, type, requireToken: true, explain
  });
  if(explain) {
    // return explain result
    return record;
  }

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
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<Array> | ExplainObject} - Return a Promise that resolves
 *   to tokens or an ExplainObject if `explain=true`.
 */
export async function getAll({accountId, email, type, explain = false} = {}) {
  assert.optionalString(accountId, 'accountId');
  assert.optionalString(email, 'email');
  if(!(accountId || email)) {
    throw new Error('Either "accountId" or "email" is required.');
  }
  validateTokenType(type);

  // get tokens from account meta
  const record = await _getAccountRecord({
    accountId, email, type, requireToken: false, explain
  });
  if(explain) {
    // return explain result
    return record;
  }

  // check if any of the keys are undefined or null
  let result = record.meta?.['bedrock-authn-token']?.tokens?.[type] ?? [];

  result = Array.isArray(result) ? result : [result];
  const allTokens = result;
  const tokens = [];
  const expiredTokens = [];
  const now = new Date();
  for(const token of result) {
    // token.expires was a Date instance when it was inserted into MongoDB
    // and it is therefore a Date instance when it comes out which makes this
    // a valid comparison
    if(token.expires > now) {
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
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise | ExplainObject} - Returns a Promise that resolves once
 *   the operation completes or an ExplainObject if `explain=true`.
 */
export async function remove({accountId, type, id, explain = false} = {}) {
  assert.string(accountId, 'accountId');
  assert.optionalString(id, 'id');
  validateTokenType(type);

  const query = {id: database.hash(accountId)};
  let update;
  const tokenTypeKey = `meta.bedrock-authn-token.tokens.${type}`;
  if(id && type === 'nonce') {
    update = {
      $pull: {
        [tokenTypeKey]: {id}
      }
    };
  } else {
    update = {
      $unset: {
        [tokenTypeKey]: true
      }
    };
  }

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  // remove token from meta
  const result = await database.collections.account.updateOne(
    query, update, database.writeOptions);

  if(result.result.n === 0) {
    throw new BedrockError(
      'Could not set account token. Account or token not found.',
      'NotFoundError', {httpStatusCode: 404, public: true});
  }
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
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<object> | ExplainObject} - Returns a Promise that resolves
 *   to an object containing the account ID, the account `email`, and token
 *   information if verified, `false` if not or returns an ExplainObject
 *   if `explain=true`.
 */
export async function verify({
  accountId, email, type, hash, challenge, clientId,
  authenticatedMethods = [], explain = false
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

  if(!explain) {
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
  }

  // get token from account meta
  const record = await _getAccountRecord({
    accountId, email, type, requireToken: true, explain
  });
  if(explain) {
    // return explain result
    return record;
  }

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

/**
 * Sets required authentication methods for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} options.accountId - The ID of the account.
 * @param {Array} options.requiredAuthenticationMethods - An optional,
 *   application specific set of authentication methods (specified by ID)
 *   that must first be satisfied before this token can be verified.
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise | ExplainObject} - Returns a Promise that resolves once
 *   the operation completes or an ExplainObject if `explain=true`.
 */
export async function setAuthenticationRequirements({
  accountId, requiredAuthenticationMethods, explain = false
} = {}) {
  assert.string(accountId, 'accountId');
  assert.array(requiredAuthenticationMethods, 'requiredAuthenticationMethods');

  // add token to meta
  const query = {id: database.hash(accountId)};

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  const result = await database.collections.account.updateOne(
    query, {
      $set: {
        'meta.bedrock-authn-token.requiredAuthenticationMethods':
          requiredAuthenticationMethods
      }
    }, database.writeOptions);
  if(result.result.n === 0) {
    // check if account exists
    if(!await brAccount.exists({id: accountId})) {
      throw new BedrockError(
        'Could not set account required authentication methods. ' +
        'Account not found.',
        'NotFoundError', {httpStatusCode: 404, public: true});
    }
  }
}

/**
 * Gets required authentication methods for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} options.accountId - The ID of the account.
 *
 * @returns {Promise} - A Promise that resolves to
 *   {requiredAuthenticationMethods}.
 */
export async function getAuthenticationRequirements({accountId} = {}) {
  assert.string(accountId, 'accountId');

  const {meta} = await brAccount.get({id: accountId});
  const data = meta['bedrock-authn-token'] || {};
  const {requiredAuthenticationMethods = []} = data;

  return {requiredAuthenticationMethods};
}

/**
 * Checks if the given authenticated methods meet the given required
 * authentication methods.
 *
 * @param {object} options - The options to use.
 * @param {Array} options.requiredAuthenticationMethods - The required
 *   authentication methods.
 * @param {Array} options.authenticatedMethods - The authenticated methods.
 *
 * @returns {Promise<boolean>} - A Promise that resolves to `true` if met,
 *   `false` if not.
 */
export async function checkAuthenticationRequirements({
  requiredAuthenticationMethods, authenticatedMethods
} = {}) {
  assert.array(requiredAuthenticationMethods, 'requiredAuthenticationMethods');

  // each element in `requiredAuthenticationMethods` may be either a single
  // string or an array of strings where each string identifies an
  // authentication method; an array of strings indicates choice: any one of
  // the identifiers may be used to fulfill that dependency
  // Note: Code assumes no degenerative cases exist where
  // `requiredAuthenticationMethods` expresses an OR condition that includes a
  // method that is listed in two places; no method should be "equivalent" for
  // two different factors, will "fail closed" if this assumption is invalid
  const unmet = requiredAuthenticationMethods.slice();
  for(const m of authenticatedMethods) {
    for(const [i, d] of unmet.entries()) {
      const match = Array.isArray(d) ? m => d.includes(m) : m => d === m;
      if(match(m)) {
        unmet.splice(i, 1);
        break;
      }
    }
  }
  return unmet.length === 0;
}

/**
 * Sets a recovery email address for an account and optionally notifies the
 * account holder of the change.
 *
 * @param {object} options - The options to use.
 * @param {string} options.accountId - The ID of the account to set the
 *   recovery email for.
 * @param {string} options.recoveryEmail - The recovery email to set.
 * @param {boolean} [options.notify=true] - Set to `true` to notify the account
 *   user, `false` not to.
 *
 * @returns {Promise} - A Promise that resolves once the operation completes.
 */
export async function setRecoveryEmail({
  accountId, recoveryEmail, notify = true
} = {}) {
  assert.string(accountId, 'accountId');
  assert.string(recoveryEmail, 'recoveryEmail');

  // create a patch to set the new recover email
  const record = await brAccount.get({id: accountId});
  const oldRecoveryEmail = record.account.recoveryEmail;
  const observer = jsonpatch.observe(record.account);
  record.account.recoveryEmail = recoveryEmail;
  const patch = jsonpatch.generate(observer);
  jsonpatch.unobserve(record.account, observer);

  // apply the patch
  await brAccount.update({
    id: accountId,
    patch,
    sequence: record.meta.sequence
  });

  if(notify) {
    const event = {
      account: accountId,
      email: record.account.email,
      oldRecoveryEmail,
      newRecoveryEmail: recoveryEmail
    };

    try {
      await bedrock.events.emit(
        `bedrock-authn-token.recoveryEmail.change`, event);
    } catch(e) {
      logger.error('Failed to notify user of recovery email change.', {
        account: accountId,
        oldRecoveryEmail,
        newRecoveryEmail: recoveryEmail,
        error: e
      });
    }
  }
}

// exported for testing purposes
export async function _getAccountRecord({
  accountId, email, id, type, requireToken, explain
} = {}) {
  // tokens are found in account meta; query accordingly
  const typeKey = `meta.bedrock-authn-token.tokens.${type}`;
  const query = {};
  if(requireToken) {
    query[typeKey] = {$exists: true};
  }
  const projection = {
    _id: 0, 'account.id': 1, 'account.email': 1, [typeKey]: 1
  };
  if(accountId) {
    query.id = database.hash(accountId);
  } else {
    query['account.email'] = email;
  }

  if(id) {
    const tokenIdKey = 'meta.bedrock-authn-token.tokens.nonce.id';
    query[tokenIdKey] = id;
  }

  if(explain) {
    // 'find().limit(1)' is used here because 'findOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(
      query, {projection}).limit(1);
    return cursor.explain('executionStats');
  }

  const record = await database.collections.account.findOne(
    query, {projection});
  if(!record) {
    const subject = requireToken ? 'Authentication token' : 'Account';
    throw new BedrockError(`${subject} not found.`, {
      name: 'NotFoundError',
      details: {
        httpStatusCode: 404,
        public: true
      }
    });
  }
  return record;
}

/**
 * An object containing information on the query plan.
 *
 * @typedef {object} ExplainObject
 */
