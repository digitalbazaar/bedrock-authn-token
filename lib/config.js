/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';

const cfg = config['authn-token'] = {};

// an array of strings like 'login-email-challenge' that will be added to
// new accounts if no other `requiredAuthenticationMethods` are set
cfg.defaultRequiredAuthenticationMethods = [];

cfg.pbkdf2 = {
  id: 'pbkdf2-sha512',
  saltSize: 16,
  iterations: 100000,
  minIterations: 100000
};

cfg.nonce = {
  defaults: {
    // 10 minute expiration
    ttl: 10 * 60 * 1000
  },
  maxNonceCount: 5
};

cfg.totp = {
  // default and most commonly used algorithm is SHA-1
  algorithm: 'SHA-1',
  // default period and most commonly used is 30 (seconds)
  period: 30,
  // default and most commonly used digits is 6
  digits: 6,
  // allow delta of +/-1 time period for code verification
  window: 1
};

// a hash prefix is used for tokens to ensure that the stored hashes are
// unique to the application (in the event that external systems also hash
// the secret inputs for some other use case, the hashes stored on this
// system will not match the ones there or vice versa)
// **DEPRECATED**: To be removed in a future version
cfg.hashPrefix = 'bedrock-authn-token:';
