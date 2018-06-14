/*
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
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
    ttl: 10 * 60 * 1000
  }
};
