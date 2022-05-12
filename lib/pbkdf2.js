/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import {assert} from './assert.js';
import crypto from 'node:crypto';
import {promisify} from 'util';

const {util: {BedrockError}} = bedrock;

const subtle = _getCryptoSubtle();
const getRandomValues = _getRandomValues();

const ALGORITHM = {name: 'PBKDF2'};
const EXTRACTABLE = false;
const KEY_USAGE = ['deriveBits', 'deriveKey'];

/**
 * Derive key bits from a password.
 *
 * @param {object} options - The options to use.
 * @param {number} options.bitLength - The number of bytes to derive.
 * @param {number} [options.iterations=100000] - The number of iterations to
 *   use.
 * @param {string} options.password - The password to use.
 * @param {Uint8Array} [options.salt] - The salt to use; one will be
 *   generated if not provided.
 * @param {number} [options.saltSize] - The salt size, in bytes, to generate,
 *   if `salt` was not provided.
 *
 * @returns {Promise<Uint8Array>} The derived bits.
 */
export async function pbkdf2({
  bitLength = 512, iterations = 100000, password, salt, saltSize = 16
} = {}) {
  assert.nonNegativeSafeInteger(bitLength, 'bitLength');
  assert.nonNegativeSafeInteger(iterations, 'iterations');
  assert.string(password, 'password');
  if(salt !== undefined) {
    if(typeof salt === 'string') {
      salt = new Uint8Array(Buffer.from(salt, 'base64'));
    } else {
      assert.uint8Array(salt, 'salt');
    }
  } else {
    assert.nonNegativeSafeInteger(saltSize, 'saltSize');
    salt = getRandomValues(new Uint8Array(saltSize));
  }

  const kdk = await subtle.importKey(
    'raw', new TextEncoder().encode(password),
    ALGORITHM, EXTRACTABLE, KEY_USAGE);

  const algorithm = {
    ...ALGORITHM,
    salt,
    iterations,
    // choose slowest commonly available hash
    hash: 'SHA-512'
  };
  const derivedBits = new Uint8Array(
    await subtle.deriveBits(algorithm, kdk, bitLength));
  const phc = {
    id: 'pbkdf2-sha512',
    params: {i: iterations},
    salt: toBase64NoPad(salt),
    hash: toBase64NoPad(derivedBits)
  };
  const hash = serializePhc({phc});
  return {algorithm, salt, derivedBits, hash, phc};
}

// password hashing competition (PHC) format
// https://github.com/P-H-C/phc-string-format
export function serializePhc({phc}) {
  // e.g. $pbkdf2-sha512$i=<iterations>$<base64 salt>$<base64 derivedBits>
  const {id, params, salt, hash} = phc;
  const paramString = Object.entries(params).map(kv => kv.join('=')).join(',');
  const b64Salt = typeof salt === 'string' ? salt : toBase64NoPad(salt);
  const b64Hash = typeof hash === 'string' ? hash : toBase64NoPad(hash);
  return `$${id}$${paramString}$${b64Salt}$${b64Hash}`;
}

export function deserializePhc({hash: serialized} = {}) {
  const [, id, paramString, salt, hash] = serialized.split('$');
  if(id !== 'pbkdf2-sha512') {
    throw new BedrockError(
      `Unsupported hash algorithm "${id}".`, {
        name: 'SyntaxError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  const params = Object.fromEntries(
    paramString.split(',').map(p => p.split('=')));

  // parse integers
  for(const key in params) {
    const num = parseInt(params[key], 10);
    if(num.toString() === params[key]) {
      params[key] = num;
    }
  }

  if(Object.keys(params).length !== 1 || typeof params.i !== 'number') {
    throw new BedrockError(
      `Unsupported parameters "${paramString}".`, {
        name: 'SyntaxError',
        details: {
          httpStatusCode: 400,
          public: true
        }
      });
  }

  return {id, params, salt, hash};
}

export function toBase64NoPad(x) {
  return Buffer.from(x).toString('base64').split('=')[0];
}

function _getCryptoSubtle() {
  const subtle = crypto?.webcrypto?.subtle ?? {};
  if(subtle.importKey) {
    return subtle;
  }

  const pbkdf2 = promisify(crypto.pbkdf2);

  // local polyfill supports just `pbkdf2`
  subtle.importKey = async function importKey(format, secret) {
    return {format, secret};
  };
  subtle.deriveBits = async function deriveBits(algorithm, key, bitLength) {
    const {secret} = key;
    const {salt, iterations} = algorithm;
    const byteLength = bitLength / 8;
    if(algorithm.hash !== 'SHA-512') {
      throw new Error(`Unsupported hash algorithm "${algorithm.hash}".`);
    }
    const hash = 'sha512';
    const derivedKey = await pbkdf2(secret, salt, iterations, byteLength, hash);
    // clear secret
    secret.fill(0);
    return new Uint8Array(derivedKey);
  };

  return subtle;
}

function _getRandomValues() {
  if(crypto?.webcrypto?.getRandomValues) {
    return crypto.webcrypto.getRandomValues;
  }

  if(crypto.randomFill) {
    return promisify(crypto.randomFill);
  }

  throw new Error(
    '"crypto.webcrypto.getRandomValues" or "crypto.randomFill" required.');
}
