/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-account');
const bedrock = require('bedrock');

// load config defaults
require('./config');

// module API
const api = {};
module.exports = api;

api.notify = async ({
  actor, account, email, authenticationMethod, notification, token
}) => {
  // emit event for another module to handle
  const event = {
    actor,
    account,
    email,
    token,
    authenticationMethod,
    notification
  };
  await bedrock.events.emit('bedrock-authn-token.notify', event);
};
