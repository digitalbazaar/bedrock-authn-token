/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import '@bedrock/account';
import assert from 'assert-plus';
import {createRequire} from 'node:module';
import crypto from 'node:crypto';
import {promisify} from 'node:util';
const require = createRequire(import.meta.url);
const {generateId} = require('bnid');

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
    return generateId({fixedLength: true});
  }
  throw new Error(
    `Invalid "entryStyle" "${entryStyle}"; "entryStyle" must ` +
    'be "human" or "machine".');
}

export function fastHash({clientId, hash, prefix = false} = {}) {
  const hashFn = prefix ? _prefixedHash : _sha256;
  if(clientId) {
    return hashFn(`${hash}:${clientId}`);
  }
  return hashFn(hash);
}

export function verifyHash({clientId, hash, sha256} = {}) {
  // prefix hash if using legacy bcrypt tokens
  const prefix = hash.startsWith('$2b');
  // FIXME: if `sha256` is already a buffer, do not decode, just pass it
  return crypto.timingSafeEqual(
    Buffer.from(sha256, 'base64'),
    Buffer.from(fastHash({clientId, hash, prefix}), 'base64'));
}

// legacy format for legacy bcrypt tokens
function _prefixedHash(x) {
  const {hashPrefix} = config['authn-token'];
  return _sha256(`${hashPrefix}${x}`);
}

function _sha256(x) {
  return crypto.createHash('sha256').update(x).digest('base64');
}
