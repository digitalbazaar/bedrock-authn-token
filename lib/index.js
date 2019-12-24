/*
 * Copyright (c) 2018-2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-account');
const assert = require('assert-plus');
const bedrock = require('bedrock');
const bcrypt = require('bcrypt');
const {config} = bedrock;
const crypto = require('crypto');
const database = require('bedrock-mongodb');
const brPermission = require('bedrock-permission');
const {promisify} = require('util');
const brPermissionCheck = promisify(brPermission.checkPermission);
const randomBytes = promisify(crypto.randomBytes);
const {BedrockError} = bedrock.util;

// load config defaults
require('./config');

// module API
const api = {};
module.exports = api;

const PERMISSIONS = bedrock.config.permission.permissions;
const TOKEN_TYPES = ['password', 'nonce', 'challenge'];
// base58 alphabet; used to improve human readability
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// a hash prefix is used for tokens to ensure that the stored hashes are
// unique to this library (in the event that external systems also hash
// the secret inputs for some other use case, the hashes stored on this
// system will not match the ones there or vice versa)
const HASH_INPUT_PREFIX = 'bedrock-authn-token:';

const logger = bedrock.loggers.get('app').child('bedrock-authn-token');

/**
 * Sets a token for an account.
 *
 * @param actor the actor or capabilities to perform the action.
 * @param [account] the ID of the account to set a token for.
 * @param [email] the email address for the account to set a token for.
 * @param type the type of token to set.
 * @param [hash] the bcrypt hash to use to set a password token.
 * @param [notify=true] `true` to notify the account user, `false` not to.
 *
 * @return a Promise that resolves once the operation completes.
 */
api.set = async ({actor, account, email, type, hash, notify = true}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(email, 'email');
  validateTokenType(type);
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  if(account && email) {
    throw new Error('Only "account" or "email" must be given.');
  }

  const token = {};
  let challenge;

  if(type === 'password') {
    assert.string(hash, 'hash');
    validateBcryptHash(hash);
    token.salt = getBcryptSalt(hash);
    token.sha256 = prefixedHash(hash);
  } else if(type === 'nonce') {
    // if there is an existing, unexpired nonce, reuse it, do not generate
    // a new one to avoid DoS attack of constantly running bcrypt algorithm
    try {
      const existingToken = await api.get({actor: null, account, email, type});
      // keep existing token if it hasn't expired; note that there is no
      // `challenge` to return because it is not known in the database
      if(existingToken && new Date() < new Date(existingToken.expires)) {
        return {type};
      }
    } catch(e) {
      if(e.name !== 'NotFoundError') {
        throw e;
      }
    }

    const cfg = config['authn-token'];
    const {ttl} = cfg.nonce.defaults;

    // generate new token
    challenge = await generateNonce();
    const salt = await bcrypt.genSalt(cfg.bcrypt.rounds);
    const hash = await bcrypt.hash(challenge, salt);
    token.salt = salt;
    token.sha256 = prefixedHash(hash);
    token.expires = new Date(Date.now() + ttl);
  } else if(type === 'challenge') {
    // TODO: implement
    throw new Error('Not implemented.');
  }

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_UPDATE, {resource: [account]});

  // add token to meta
  const query = {};
  if(account) {
    query.id = database.hash(account);
  } else {
    query['account.email'] = email;
  }
  const result = await database.collections.account.update(
    query, {
      $set: {
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
        actor, account, email, type, challenge, notification: {type: 'create'}
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

  return {type, challenge};
};

/**
 * Gets a token for an account.
 *
 * @param actor the actor or capabilities to perform the action.
 * @param [account] the ID of the account.
 * @param [email] the email of the account.
 * @param type the type of token to get.
 *
 * @return a Promise that resolves to the token.
 */
api.get = async ({actor, account, email, type}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(account, 'email');
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
  const record = await database.collections.account.findOne(
    query, {_id: 0, [typeKey]: 1});
  if(!record) {
    throw new BedrockError('Authentication token not found.', 'NotFoundError', {
      httpStatusCode: 404,
      public: true
    });
  }

  return record.meta['bedrock-authn-token'].tokens[type];
};

/**
 * Removes a token from an account.
 *
 * @param actor the actor or capabilities to perform the action.
 * @param account the ID of the account to remove a token from.
 * @param type the type of token to remove.
 *
 * @return a Promise that resolves once the operation completes.
 */
api.remove = async ({actor, account, type}) => {
  assert.string(account, 'account');
  validateTokenType(type);

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_UPDATE, {resource: [account]});

  // remove token from meta
  const result = await database.collections.account.update({
    id: database.hash(account)
  }, {
    $unset: {
      [`meta.bedrock-authn-token.tokens.${type}`]: true
    }
  }, database.writeOptions);
  if(result.result.n === 0) {
    throw new BedrockError(
      'Could not set account token. Account or token not found.',
      'NotFoundError', {httpStatusCode: 404, public: true});
  }
};

/**
 * Verifies a token for an account.
 *
 * @param actor the actor or capabilities to perform the action.
 * @param [account] the ID of the account to verify a token for.
 * @param [email] the email of the account to verify a token for.
 * @param type the type of token to verify.
 * @param hash the bcrypt hash of the token to verify.
 *
 * @return a Promise that resolves to an Account if verified, `false` if not.
 */
api.verify = async ({actor, account, email, type, hash}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(account, 'email');
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  validateTokenType(type);
  assert.string(hash, 'hash');
  validateBcryptHash(hash);

  // TODO: could call `api.get()` here if not for the need for
  //  `record.account.id` at the end
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
  const record = await database.collections.account.findOne(
    query, {_id: 0, account: 1, [typeKey]: 1});
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

  if(type === 'challenge') {
    // TODO: implement challenge check
    // compare challenge results against challenge token; on success, write
    // that the challenge was met to database
    // possible challenges are small PoW like find factors to produce challenge
    // number
    throw new Error('Not implemented.');
  }
console.log('token type', type);
console.log('token.sha256', token.sha256);
console.log('prefixed hash', prefixedHash(hash));
  const verified = crypto.timingSafeEqual(
    new Buffer(token.sha256, 'base64'),
    new Buffer(prefixedHash(hash), 'base64'));
  if(verified) {
    // return account
    return {
      id: record.account.id,
      email: record.account.email || null
    };
  }
  return false;
};

api.notify = async ({actor, account, email, type, challenge, notification}) => {
  // emit event for another module to handle
  const event = {
    actor,
    account,
    email,
    type,
    challenge,
    notification
  };
  await bedrock.events.emit('bedrock-authn-token.notify', event);
};

function validateTokenType(type) {
  assert.string(type, 'type');
  if(!TOKEN_TYPES.includes(type)) {
    throw new Error('Token "type" must be one of: ' + TOKEN_TYPES.join(', '));
  }
}

function validateBcryptHash(hash) {
  const cfg = config['authn-token'].bcrypt;
  const parsedHash = hash.substr(1).split('$');
  if(hash.length === 60 &&
    hash[0] === '$' &&
    parsedHash.length === 3 &&
    // version 2x salt
    parsedHash[0][0] === '2' &&
    parseInt(parsedHash[1], 10) >= cfg.rounds) {
    return true;
  }

  throw new BedrockError(
    'Invalid token.', 'SyntaxError', {
      httpStatusCode: 400,
      public: true
    });
}

function getBcryptSalt(hash) {
  // assumes v2 salt w/length of 29
  return hash.substr(0, 29);
}

function prefixedHash(x) {
  return sha256(HASH_INPUT_PREFIX + x);
}

function sha256(x) {
  return crypto.createHash('sha256').update(x).digest('base64');
}

// generates a 9 char nonce that can be split into 3 groups for readability
async function generateNonce() {
  const bytes = await randomBytes(9);
  const length = ALPHABET.length - 1;
  return [...bytes].map(b => ALPHABET[Math.floor(b / 255 * length)]).join('');
}
