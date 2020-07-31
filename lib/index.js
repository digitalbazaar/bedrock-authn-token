/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-account');
const assert = require('assert-plus');
const bedrock = require('bedrock');
const bcrypt = require('bcrypt');
const brAccount = require('bedrock-account');
const brPermission = require('bedrock-permission');
const {promisify} = require('util');
const brPermissionCheck = promisify(brPermission.checkPermission);
const {config} = bedrock;
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const jsonpatch = require('fast-json-patch');
const {authenticator} = require('otplib');
const {BedrockError} = bedrock.util;
const {
  generateNonce,
  getBcryptSalt,
  prefixedHash,
  validateBcryptHash,
  validateTokenType
} = require('./helpers');
const {generateId} = require('bnid');

// load config defaults
require('./config');

const logger = require('./logger');

// module API
const api = {};
module.exports = api;

api.notify = require('./notify').notify;
api.clients = require('./clients');

const PERMISSIONS = bedrock.config.permission.permissions;

/**
 * Sets a token for an account.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {string} [options.account] - The ID of the account to set a token for.
 * @param {string} [options.email] - The email address for the account to set a
 *   token for.
 * @param {string} options.type - The type of token to set.
 * @param {string} [options.clientId] - An identifier for the client to bind a
 *   token to, if supported by the token type.
 *  @param {string} [options.serviceId] - An identifier to associate with the
 *   token. For TOTP tokens, `serviceId` is encoded in the `otpAuthUrl` value
 *   returned by this API.
 * @param {string} [options.hash] - The bcrypt hash to use to set a
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
 * @returns {Promise<object>} - A Promise that resolves once the operation
 *   completes with optional token details depending on the type.
 */
api.set = async ({
  actor, account, email, type, clientId, serviceId, hash,
  authenticationMethod = type, requiredAuthenticationMethods = [],
  notify = true, typeOptions = {entryStyle: 'human'}
} = {}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(email, 'email');
  assert.optionalString(clientId, 'clientId');
  assert.optionalString(serviceId, 'serviceId');
  validateTokenType(type);
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  if(account && email) {
    throw new Error('Only "account" or "email" must be given.');
  }

  // FIXME: this code is problematic if `account` is not set (likely being
  // skipped when actor is null, but don't have test coverage when it isn't)
  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_UPDATE, {resource: [account]});

  const token = {
    authenticationMethod,
    requiredAuthenticationMethods
  };

  // generate 128-bit random ID for token, sufficiently large to avoid conflict
  token.id = await generateId({
    fixedLength: true
  });

  const rValue = {
    type,
    id: token.id,
  };
  let challenge;

  if(type === 'password') {
    assert.string(hash, 'hash');
    validateBcryptHash(hash);
    token.salt = getBcryptSalt(hash);
    token.sha256 = prefixedHash(hash);
  } else if(type === 'nonce') {
    // FIXME: may need to allow up to N tokens, one per `clientId` if
    // `clientId` is set
    const cfg = config['authn-token'];
    const {maxNonceCount} = cfg.nonce.defaults;
    let existingTokens;
    try {
      // check if nonce exists
      existingTokens = await api.getAll({
        actor: null, account, email, type, filterExpiredTokens: false
      });
    } catch(e) {
      if(e.name !== 'NotFoundError') {
        throw e;
      }
    }
    let removeCount = 0;
    if(existingTokens) {
      const now = Date.now();
      for(const existingToken of existingTokens) {
        // check if existing token has expired
        if(existingToken && now > existingToken.expires) {
          try {
            // the `nonce` has expired, delete it
            await api.remove({actor, account, type, id: existingToken.id});
            removeCount++;
          } catch(e) {
            if(e.name !== 'NotFoundError') {
              throw e;
            }
          }
        }
      }
      // If existingTokens exceeds maxNonceCount, throw `NotAllowed` error
      const existingTokensLength = existingTokens.length - removeCount;
      if(existingTokensLength >= maxNonceCount) {
        throw new BedrockError(
          `Existing tokens exceeds maxNonceCount of ${maxNonceCount}.`,
          'NotAllowedError', {
            httpStatusCode: 400,
            public: true
          });
      }
    }

    const {ttl} = cfg.nonce.defaults;

    // generate new token
    challenge = await generateNonce(typeOptions);
    const salt = await bcrypt.genSalt(cfg.bcrypt.rounds);
    let hash;
    // if client ID (e.g., a session ID) is given, concatenate with `:` to the
    // challenge before hashing
    if(clientId !== undefined) {
      hash = await bcrypt.hash(`${challenge}:${clientId}`, salt);
    } else {
      hash = await bcrypt.hash(challenge, salt);
    }
    token.salt = salt;
    token.sha256 = prefixedHash(hash);
    token.expires = new Date(Date.now() + ttl);

    // return challenge
    rValue.challenge = challenge;
  } else if(type === 'challenge') {
    // TODO: implement
    throw new Error('Not implemented.');
  } else if(type === 'totp') {
    // check for existing totp secret
    let err;
    try {
      await api.get({actor: null, account, email, type});
    } catch(e) {
      if(e.name !== 'NotFoundError') {
        throw e;
      }
      err = e;
    }
    // a NotFoundError is expected here
    if(!err) {
      throw new BedrockError(
        'TOTP authentication token already set.', 'DuplicateError', {
          httpStatusCode: 409,
          public: true
        });
    }

    // get email for use in label/url
    if(!email) {
      const record = await brAccount.get({actor, id: account});
      if(record.account.email) {
        email = record.account.email;
      }
    }

    // FIXME: save params in token and use explicitly? (algorithm, digits, step)
    token.secret = authenticator.generateSecret();

    // defaults
    const allOptions = authenticator.allOptions();

    // return TOTP params
    // algorithm, digits, period are defaults for otplib 'authenticator'
    rValue.secret = token.secret;
    // FIXME: use readable email and service name
    rValue.label = email || account;
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
  if(account) {
    query.id = database.hash(account);
  } else {
    query['account.email'] = email;
  }
  const updateType = type === 'nonce' ? '$push' : '$set';
  const result = await database.collections.account.updateMany(
    query, {
      [updateType]: {
        [`meta.bedrock-authn-token.tokens.${type}`]: token
      }
    }, database.writeOptions);

  if(result.result.n === 0) {
    throw new BedrockError(
      'Could not set account token. Account not found.',
      'NotFoundError', {httpStatusCode: 404, public: true});
  }

  if(notify) {
    try {
      await api.notify({
        actor, account, email, authenticationMethod,
        // do not include hash, salt, or other properties for verify
        // Note: however, `id` may be used in conjunction with `account`
        // or `email` in a deep link for authentication
        token: {id: token.id, type, challenge},
        notification: {type: 'create'}
      });
    } catch(e) {
      logger.error('Failed to notify user of token creation.', {
        account,
        email,
        type,
        error: e
      });
    }
  }

  return rValue;
};

/**
 * Gets a token for an account.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {string} [options.account] - The ID of the account.
 * @param {string} [options.email] - The email of the account.
 * @param {string} options.type - The type of token to get.
 * @param {string} options.id - The id of the token to get.
 * @param {boolean} [options.filterExpiredTokens] - Set to `true` to drop
 *   expired token and to `false` to get token even if it is expired.
 *
 * @returns {Promise<object>} - A Promise that resolves to the token.
 */
api.get = async ({
  actor, account, email, type, id, filterExpiredTokens = true
} = {}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(email, 'email');
  assert.optionalString(id, 'id');
  assert.optionalBool(filterExpiredTokens, 'filterExpiredTokens');

  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  validateTokenType(type);

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_ACCESS, {resource: [account]});

  // get token from meta
  const typeKey = `meta.bedrock-authn-token.tokens.${type}`;
  const query = {[typeKey]: {$exists: true}};
  if(account) {
    query.id = database.hash(account);
  } else {
    query['account.email'] = email;
  }

  const tokenId = 'meta.bedrock-authn-token.tokens.nonce.id';
  if(id) {
    query[tokenId] = id;
  }

  const record = await database.collections.account.findOne(
    query, {projection: {_id: 0, [typeKey]: 1}});

  if(!record) {
    throw new BedrockError(
      'Authentication token not found.',
      'NotFoundError', {
        httpStatusCode: 404,
        public: true
      });
  }

  let result = record.meta['bedrock-authn-token'].tokens[type];
  let rValue;
  if(type === 'nonce') {
    if(id) {
      result = result.filter(token => token.id === id);
    }
    rValue = result[0];
  } else {
    rValue = result;
  }
  // filter expired token.
  if(filterExpiredTokens) {
    const now = Date.now();
    if(rValue.expires < now) {
      // throw NotFoundError
      throw new BedrockError(
        'Authentication token has expired.',
        'NotFoundError', {
          httpStatusCode: 404,
          public: true
        });
    }
  }
  return rValue;
};

/**
 * Gets tokens for an account.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {string} [options.account] - The ID of the account.
 * @param {string} [options.email] - The email of the account.
 * @param {string} options.type - The type of tokens to get.
 * @param {boolean} [options.filterExpiredTokens] - Set to `true` to drop
 *   expired token and to `false` to get token even if it is expired.
 *
 * @returns {Promise<Array>} - A Promise that resolves to tokens.
 */
api.getAll = async ({
  actor, account, email, type, filterExpiredTokens = true
} = {}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(email, 'email');
  assert.optionalBool(filterExpiredTokens, 'filterExpiredTokens');

  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  validateTokenType(type);

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_ACCESS, {resource: [account]});

  // get tokens from meta
  const typeKey = `meta.bedrock-authn-token.tokens.${type}`;
  const query = {[typeKey]: {$exists: true}};
  if(account) {
    query.id = database.hash(account);
  } else {
    query['account.email'] = email;
  }
  const record = await database.collections.account.findOne(
    query, {projection: {_id: 0, [typeKey]: 1}});

  if(!record) {
    throw new BedrockError('Authentication token not found.', 'NotFoundError', {
      httpStatusCode: 404,
      public: true
    });
  }
  let result = record.meta['bedrock-authn-token'].tokens[type];
  result = type === 'nonce' ? result : [result];
  const now = Date.now();
  if(filterExpiredTokens) {
    return result.filter(token => token.expires > now);
  }
  return result;
};

/**
 * Removes a token from an account.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {string} options.account - The ID of the account to remove a token
 *   from.
 * @param {string} options.type - The type of token to remove.
 * @param {string} [options.id] - The id of the token to be removed.
 *
 * @returns {Promise} - A Promise that resolves once the operation completes.
 */
api.remove = async ({actor, account, type, id} = {}) => {
  assert.string(account, 'account');
  assert.optionalString(id, 'id');
  validateTokenType(type);

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_UPDATE, {resource: [account]});
  let update;
  const tokenTypeKey = `meta.bedrock-authn-token.tokens.${type}`;
  if(type === 'nonce') {
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
  // remove token from meta
  const result = await database.collections.account.updateOne({
    id: database.hash(account),
  }, update, database.writeOptions);

  if(result.result.n === 0) {
    throw new BedrockError(
      'Could not set account token. Account or token not found.',
      'NotFoundError', {httpStatusCode: 404, public: true});
  }
};

/**
 * Verifies a token for an account.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {string} [options.account] - The ID of the account to verify a token
 *   for.
 * @param {string} [options.email] - The email of the account to verify a token
 *   for.
 * @param {string} options.type - The type of token to verify.
 * @param {string} [options.hash] - The bcrypt hash to verify for a
 *   password/nonce or other type of token that uses hashed token challenges.
 * @param {string} [options.challenge] - The token challenge value for token
 *   types that do not hash token challenges.
 * @param {Array} [options.authenticatedMethods=[]] - A list of identifiers for
 *   other methods methods that have already been authenticated (useful for
 *   multifactor verification where one method depends on other methods to
 *   first be used).
 *
 * @returns {Promise<object>} - A Promise that resolves to an object containing
 *   the account ID, the account `email`, and token information if verified,
 *   `false` if not.
 */
api.verify = async ({
  actor, account, email, type, hash, challenge, authenticatedMethods = []
} = {}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(email, 'email');
  assert.optionalArrayOfString(authenticatedMethods, 'authenticatedMethods');
  if(!(account || email)) {
    // FIXME: BedrockError
    throw new Error('Either "account" or "email" must be provided.');
  }
  validateTokenType(type);

  assert.optionalString(hash, 'hash');
  if(hash) {
    validateBcryptHash(hash);
  }

  assert.optionalString(challenge, 'challenge');
  if(!(hash || challenge)) {
    throw new SyntaxError(
      'One of "hash" or "challenge" must be provided.');
  }

  // TODO: could call `api.get()` here if not for the need for
  //  `record.account.id` at the end
  // FIXME: this code is problematic if `account` is not set (likely being
  // skipped when actor is null, but don't have test coverage when it isn't)
  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_ACCESS, {resource: [account]});

  // get token from meta
  const typeKey = `meta.bedrock-authn-token.tokens.${type}`;
  const query = {[typeKey]: {$exists: true}};
  if(account) {
    query.id = database.hash(account);
  } else {
    query['account.email'] = email;
  }
  // TODO: handle the case where an email address is associated with more
  // than one account
  const record = await database.collections.account.findOne(
    query, {projection: {_id: 0, account: 1, [typeKey]: 1}});
  if(!record) {
    throw new BedrockError('Authentication token not found.', 'NotFoundError', {
      httpStatusCode: 404,
      public: true
    });
  }

  const token = record.meta['bedrock-authn-token'].tokens[type];
  if(token.expires && new Date() >= new Date(token.expires)) {
    throw new BedrockError(
      'Authentication token has expired.',
      'NotFoundError', {
        httpStatusCode: 404,
        public: true
      });
  }

  // check that dependencies have been met ... other authentication methods
  // that must have already been used (for multifactor flows)
  const {requiredAuthenticationMethods} = token;
  if(requiredAuthenticationMethods) {
    const met = await api.checkAuthenticationRequirements({
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

  if(type === 'challenge') {
    // TODO: implement challenge check
    // compare challenge results against challenge token; on success, write
    // that the challenge was met to database
    // possible challenges are small PoW like find factors to produce challenge
    // number
    throw new Error('Not implemented.');
  }

  let verified = false;
  if(token.sha256) {
    if(!hash) {
      throw new BedrockError(
        'Authentication token challenge must be hashed.', 'DataError', {
          httpStatusCode: 400,
          public: true
        });
    }
    // verify hash-based token value
    verified = crypto.timingSafeEqual(
      new Buffer(token.sha256, 'base64'),
      new Buffer(prefixedHash(hash), 'base64'));
  } else if(type === 'totp') {
    const cfg = config['authn-token'];
    const {window} = cfg.totp;
    // FIXME: create custom instance to just set these global options once
    authenticator.options = {window};
    // test the totpToken provided to the API against the secret drawn from
    // the accounts database
    verified = authenticator.verify({token: challenge, secret: token.secret});
  } else {
    if(!challenge) {
      throw new BedrockError(
        'Authentication token challenge must not be hashed.', 'DataError', {
          httpStatusCode: 400,
          public: true
        });
    }
    // TODO: verify challenge by calling token-specific API
  }
  if(verified) {
    // `nonce` verified, remove it
    if(type === 'nonce') {
      try {
        await api.remove({actor: null, account: record.account.id, type});
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
};

/**
 * Sets required authentication methods for an account.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {string} options.account - The ID of the account.
 * @param {Array} options.requiredAuthenticationMethods - An optional,
 *   application specific set of authentication methods (specified by ID)
 *   that must first be satisfied before this token can be verified.
 *
 * @returns {Promise} - A Promise that resolves once the operation completes.
 */
api.setAuthenticationRequirements = async (
  {actor, account, requiredAuthenticationMethods}) => {
  assert.string(account, 'account');
  assert.array(requiredAuthenticationMethods, 'requiredAuthenticationMethods');

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_UPDATE, {resource: [account]});

  // add token to meta
  const query = {
    id: database.hash(account)
  };
  const result = await database.collections.account.updateOne(
    query, {
      $set: {
        'meta.bedrock-authn-token.requiredAuthenticationMethods':
          requiredAuthenticationMethods
      }
    }, database.writeOptions);
  if(result.result.n === 0) {
    // check if account exists
    if(!await brAccount.exists({actor: null, id: account})) {
      throw new BedrockError(
        'Could not set account required authentication methods. ' +
        'Account not found.',
        'NotFoundError', {httpStatusCode: 404, public: true});
    }
  }
};

/**
 * Gets required authentication methods for an account.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {object} options.account - The ID of the account.
 *
 * @returns {Promise} - A Promise that resolves to
 *   {requiredAuthenticationMethods}.
 */
api.getAuthenticationRequirements = async ({actor, account}) => {
  assert.string(account, 'account');

  const {meta} = await brAccount.get({actor, id: account});
  const data = meta['bedrock-authn-token'] || {};
  const {requiredAuthenticationMethods = []} = data;

  return {requiredAuthenticationMethods};
};

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
api.checkAuthenticationRequirements = async ({
  requiredAuthenticationMethods, authenticatedMethods
}) => {
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
};

/**
 * Sets a recovery email address for an account and optionally notifies the
 * account holder of the change.
 *
 * @param {object} options - The options to use.
 * @param {object} options.actor - The actor or capabilities to perform the
 *   action.
 * @param {string} options.account - The ID of the account to set the recovery
 *   email for.
 * @param {string} options.recoveryEmail - The recovery email to set.
 * @param {boolean} [options.notify=true] - Set to `true` to notify the account
 *   user, `false` not to.
 *
 * @returns {Promise} - A Promise that resolves once the operation completes.
 */
api.setRecoveryEmail = async (
  {actor, account, recoveryEmail, notify = true} = {}) => {
  assert.string(account, 'account');
  assert.string(recoveryEmail, 'recoveryEmail');

  // create a patch to set the new recover email
  const record = await brAccount.get({actor, id: account});
  const oldRecoveryEmail = record.account.recoveryEmail;
  const observer = jsonpatch.observe(record.account);
  record.account.recoveryEmail = recoveryEmail;
  const patch = jsonpatch.generate(observer);
  jsonpatch.unobserve(record.account, observer);

  // apply the patch
  await brAccount.update({
    actor,
    id: account,
    patch,
    sequence: record.meta.sequence
  });

  if(notify) {
    const event = {
      actor,
      account,
      email: record.account.email,
      oldRecoveryEmail,
      newRecoveryEmail: recoveryEmail
    };

    try {
      await bedrock.events.emit(
        `bedrock-authn-token.recoveryEmail.change`, event);
    } catch(e) {
      logger.error('Failed to notify user of recovery email change.', {
        account,
        oldRecoveryEmail,
        newRecoveryEmail: recoveryEmail,
        error: e
      });
    }
  }
};
