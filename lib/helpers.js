/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {config} from '@bedrock/core';
import crypto from 'node:crypto';
import {generateId} from 'bnid';
import {promisify} from 'node:util';

const randomBytes = promisify(crypto.randomBytes);

// load config defaults
import './config.js';

const TOKEN_TYPES = ['password', 'nonce', 'totp'];

// numeric-only digits for human readibility and easy mobile entry
const NUMERIC_DIGITS = '0123456789';

export function validateTokenType(type) {
  assert.string(type, 'type');
  if(!TOKEN_TYPES.includes(type)) {
    throw new Error('Token "type" must be one of: ' + TOKEN_TYPES.join(', '));
  }
}

export async function generateNonce({entryStyle = 'human'} = {}) {
  if(entryStyle === 'human') {
    const bytes = await randomBytes(6);
    const length = NUMERIC_DIGITS.length - 1;
    return [...bytes].map(b => NUMERIC_DIGITS[Math.floor(b / 255 * length)])
      .join('');
  }
  if(entryStyle === 'machine') {
    return generateId();
  }
  throw new Error(
    `Invalid "entryStyle" "${entryStyle}"; "entryStyle" must ` +
    'be "human" or "machine".');
}

export function fastHash({
  clientId, slowHashOrUnguessableChallenge, data, encoding, prefix = false
} = {}) {
  if(data === undefined) {
    if(clientId) {
      if(!slowHashOrUnguessableChallenge) {
        throw new TypeError(
          '"slowHashOrUnguessableChallenge" is required with "clientId".');
      }
      data = `${slowHashOrUnguessableChallenge}:${clientId}`;
    } else {
      data = slowHashOrUnguessableChallenge;
    }
  }

  const hashFn = prefix ? _prefixedHash : _sha256;
  let result = hashFn(data);
  if(encoding) {
    result = result.toString(encoding);
  }
  return result;
}

export function verifySlowHashOrUnguessableChallenge({
  clientId, slowHashOrUnguessableChallenge, sha256
} = {}) {
  // prefix fast hash if using legacy bcrypt tokens
  const prefix = slowHashOrUnguessableChallenge.startsWith('$2b');
  if(typeof sha256 === 'string') {
    // legacy base64 string format
    sha256 = Buffer.from(sha256, 'base64');
  }
  return crypto.timingSafeEqual(
    sha256, fastHash({clientId, slowHashOrUnguessableChallenge, prefix}));
}

// legacy format for legacy bcrypt tokens
function _prefixedHash(x) {
  const {hashPrefix} = config['authn-token'];
  return _sha256(`${hashPrefix}${x}`);
}

function _sha256(x) {
  return crypto.createHash('sha256').update(x).digest();
}
