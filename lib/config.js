/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {config} = require('bedrock');

const cfg = config['authn-token'] = {};

cfg.bcrypt = {
  rounds: 10
};

cfg.nonce = {
  defaults: {
    // 10 minute expiration
    ttl: 10 * 60 * 1000,
    maxNonceCount: 5,
  }
};

cfg.totp = {
  // allow 1 time period window for code verification
  // https://github.com/yeojz/otplib
  window: 1
};

// a hash prefix is used for tokens to ensure that the stored hashes are
// unique to the application (in the event that external systems also hash
// the secret inputs for some other use case, the hashes stored on this
// system will not match the ones there or vice versa)
cfg.hashPrefix = 'bedrock-authn-token:';
