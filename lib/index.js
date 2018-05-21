/*
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
require('bedrock-account');
const assert = require('assert-plus');
const bedrock = require('bedrock');
const bcrypt = require('bcrypt');
const {callbackify: brCallbackify} = bedrock.util;
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

const logger = bedrock.loggers.get('app').child('bedrock-authn-token');

/**
 * Sets a token for an account.
 *
 * @param actor the actor or capabilities to perform the action.
 * @param [account] the ID of the account to set a token for.
 * @param [email] the email address for the account to set a token for.
 * @param type the type of token to set.
 * @param [hash] the bcrypt hash to use to set a password token.
 *
 * @return a Promise that resolves once the operation completes.
 */
api.set = brCallbackify(async ({actor, account, email, type, hash}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(email, 'email');
  validateTokenToken(type);
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  if(account && email) {
    throw new Error('Only "account" or "email" must be given.');
  }

  const token = {};

  if(type === 'password') {
    assert.string(hash, 'hash');
    validateBcryptHash(hash);
    const parsed = hash.split('$')[2];
    token.salt = parsed.substr(0, 29);
    token.sha256 = sha256(hash);
  } else if(type === 'nonce') {
    const cfg = config['authn-token'];
    const nonce = await generateNonce();
    const salt = await bcrypt.genSalt(cfg.bcrypt.rounds);
    const hash = await bcrypt.hash(nonce, salt);

    const {ttl} = cfg.nonce.defaults;
    token.salt = salt;
    token.hash = hash;
    token.expires = new Date(Date.now() + ttl);

    // TODO: check `careful` (TBD name) boolean; if in careful mode,
    //   check to make sure another unexpired nonce doesn't already exist, if
    //   so, check to see if an unexpired challenge has been met, if not
    //   indicate existing nonce hasn't expired yet so user needs to wait
    //   for lockout period to expire -- if no challenge/expired challenge,
    //     create, store, and return challenge
    //   if policy indicates nonce can be created then randomly generate salt
    //   and nonce, produce bcrypt for the nonce, sha256(bcrypt(salt, nonce))
    //   and then store it
    //   ... if `careful` not set, just overwrite nonce, no other checks
    //throw new Error('Not implemented');
  } else if(type === 'challenge') {
    // TODO: implement
    throw new Error('Not implemented');
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
      'NotFound');
  }
});

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
api.get = brCallbackify(async ({actor, account, email, type}) => {
  assert.optionalstring(account, 'account');
  assert.optionalstring(account, 'email');
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  validateTokenToken(type);

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_ACCESS, {resource: [account]});

  // get token from meta
  const query = {};
  if(account) {
    query.id = database.hash(account);
  } else {
    query.email = email;
  }
  const record = await database.collections.account.findOne({
    id: database.hash(account),
    [`meta.bedrock-authn-token.tokens.${type}`]: {$exists: true}
  }, {[`meta.bedrock-authn-token.tokens.${type}`]: 1});
  if(!record) {
    throw new BedrockError('Authentication token not found.', 'NotFound', {
      httpStatusCode: 400,
      public: true
    });
  }

  return record[`meta.bedrock-authn-token.tokens.${type}`];
});

/**
 * Removes a token from an account.
 *
 * @param actor the actor or capabilities to perform the action.
 * @param account the ID of the account to remove a token from.
 * @param type the type of token to remove.
 *
 * @return a Promise that resolves once the operation completes.
 */
api.remove = brCallbackify(async ({actor, account, type}) => {
  assert.string(account, 'account');
  validateTokenToken(type);

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
      'NotFound');
  }
});

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
api.verify = brCallbackify(async ({actor, account, email, type, hash}) => {
  assert.optionalstring(account, 'account');
  assert.optionalstring(account, 'email');
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  validateTokenToken(type);
  assert.string(hash, 'hash');
  validateBcryptHash(hash);

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_ACCESS, {resource: [account]});

  // get token from meta
  const record = await database.collections.account.findOne({
    id: database.hash(account),
    [`meta.bedrock-authn-token.tokens.${type}`]: {$exists: true}
  }, {account: 1, [`meta.bedrock-authn-token.tokens.${type}`]: 1});
  if(!record) {
    throw new BedrockError('Authentication token not found.', 'NotFound', {
      httpStatusCode: 400,
      public: true
    });
  }

  const token = record[`meta.bedrock-authn-token.tokens.${type}`];
  if(token.expires) {
    if(new Date() >= new Date(token.expires)) {
      throw new BedrockError('Authentication token has expired.', 'NotFound', {
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
    throw new Error('Not implemented');
  }

  const verified = crypto.timingSafeEqual(
    new Buffer(token.sha256, 'base64'),
    new Buffer(sha256(hash), 'base64'));
  if(verified) {
    // return account
    return {
      id: record.account.id,
      email: record.account.email || null
    };
  }
  return false;
});

// TODO: add API to send nonce token to account contact point (email/sms)
api.notify = brCallbackify(async (
  {actor, account, email, type, notification}) => {
  console.log('notifying');
  //throw new Error('Not implemented');
});

function validateTokenToken(type) {
  assert.string(type, 'type');
  if(!TOKEN_TYPES.includes(type)) {
    throw new Error('Token "type" must be one of: ' + TOKEN_TYPES.join(', '));
  }
}

function validateBcryptHash(hash) {
  const cfg = config['authn-token'].bcrypt;
  const parsedHash = hash.split('$');
  if(hash.length === 60 &&
    parsedHash.length === 3 &&
    parsedHash[0] === '2a' &&
    parseInt(parsedHash[1], 10) >= cfg.rounds) {
    return true;
  }

  throw new BedrockError(
    'Invalid token.', 'SyntaxError', {
      httpStatusCode: 400,
      public: true
    });
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
