/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-account');
const assert = require('assert-plus');
const bedrock = require('bedrock');
const {config} = bedrock;
const crypto = require('crypto');
const {generateId} = require('bnid');
const {BedrockError} = bedrock.util;
const {promisify} = require('util');
const randomBytes = promisify(crypto.randomBytes);

// load config defaults
require('./config');

const TOKEN_TYPES = ['password', 'nonce', 'challenge', 'totp'];

// numeric-only digits for human readibility and easy mobile entry
const NUMERIC_DIGITS = '0123456789';

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

exports.prefixedHash = x => {
  const {hashPrefix} = config['authn-token'];
  return exports.sha256(`${hashPrefix}${x}`);
};

exports.sha256 = x => crypto.createHash('sha256').update(x).digest('base64');

exports.generateNonce = async ({entryStyle = 'human'} = {}) => {
  if(entryStyle === 'human') {
    const bytes = await randomBytes(6);
    const length = NUMERIC_DIGITS.length - 1;
    return [...bytes].map(b => NUMERIC_DIGITS[Math.floor(b / 255 * length)])
      .join('');
  }
  if(entryStyle === 'machine') {
    return generateId({
      fixedLength: true
    });
  }
  throw new Error(`Invalid "entryStyle" "${entryStyle}"; "entryStyle" must ` +
    `be "human" or "machine".`);
};

exports.combinedHash = ({clientId, hash} = {}) => {
  if(clientId) {
    return exports.prefixedHash(`${hash}:${clientId}`);
  }
  return exports.prefixedHash(hash);
};

exports.verifyHash = ({clientId, hash, sha256} = {}) => {
  return crypto.timingSafeEqual(
    Buffer.from(sha256, 'base64'),
    Buffer.from(exports.combinedHash({clientId, hash}), 'base64'));
};
