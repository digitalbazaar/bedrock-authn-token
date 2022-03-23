/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import 'bedrock-account';
import * as bedrock from 'bedrock';
import assert from 'assert-plus';
import crypto from 'crypto';
import {generateId} from 'bnid';
import {promisify} from 'util';
const {config, util: {BedrockError}} = bedrock;
const randomBytes = promisify(crypto.randomBytes);

// load config defaults
import './config.js';

const TOKEN_TYPES = ['password', 'nonce', 'challenge', 'totp'];

// numeric-only digits for human readibility and easy mobile entry
const NUMERIC_DIGITS = '0123456789';

export function validateTokenType(type) {
  assert.string(type, 'type');
  if(!TOKEN_TYPES.includes(type)) {
    throw new Error('Token "type" must be one of: ' + TOKEN_TYPES.join(', '));
  }
}

export function validateBcryptHash(hash) {
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

// assumes v2 salt w/length of 29
export function getBcryptSalt(hash) {
  return hash.substr(0, 29);
}

export function prefixedHash(x) {
  const {hashPrefix} = config['authn-token'];
  return sha256(`${hashPrefix}${x}`);
}

export function sha256(x) {
  return crypto.createHash('sha256').update(x).digest('base64');
}

export async function generateNonce({entryStyle = 'human'} = {}) {
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
  throw new Error(
    `Invalid "entryStyle" "${entryStyle}"; "entryStyle" must ` +
    'be "human" or "machine".');
}

export function combinedHash({clientId, hash} = {}) {
  if(clientId) {
    return prefixedHash(`${hash}:${clientId}`);
  }
  return prefixedHash(hash);
}

export function verifyHash({clientId, hash, sha256} = {}) {
  return crypto.timingSafeEqual(
    Buffer.from(sha256, 'base64'),
    Buffer.from(combinedHash({clientId, hash}), 'base64'));
}
