/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-account');
const assert = require('assert-plus');
const bedrock = require('bedrock');
const {config} = bedrock;
const crypto = require('crypto');
const {promisify} = require('util');
const randomBytes = promisify(crypto.randomBytes);
const {BedrockError} = bedrock.util;

// load config defaults
require('./config');

const TOKEN_TYPES = ['password', 'nonce', 'challenge'];

// base58 alphabet; used to improve human readability
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

// a hash prefix is used for tokens to ensure that the stored hashes are
// unique to this library (in the event that external systems also hash
// the secret inputs for some other use case, the hashes stored on this
// system will not match the ones there or vice versa)
const HASH_INPUT_PREFIX = 'bedrock-authn-token:';

exports.validateTokenType = type => {
  assert.string(type, 'type');
  if(!TOKEN_TYPES.includes(type)) {
    throw new Error('Token "type" must be one of: ' + TOKEN_TYPES.join(', '));
  }
};

exports.validateBcryptHash = hash => {
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
};

// assumes v2 salt w/length of 29
exports.getBcryptSalt = hash => hash.substr(0, 29);

exports.prefixedHash = x => exports.sha256(HASH_INPUT_PREFIX + x);

exports.sha256 = x => crypto.createHash('sha256').update(x).digest('base64');

// generates a `groups * 3` char nonce; output is a multiple of 3 to ease
// human readability
exports.generateNonce = async ({groups = 3} = {}) => {
  const bytes = await randomBytes(groups * 3);
  const length = ALPHABET.length - 1;
  return [...bytes].map(b => ALPHABET[Math.floor(b / 255 * length)]).join('');
};
