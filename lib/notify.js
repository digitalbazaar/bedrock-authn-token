/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

require('bedrock-account');
const bedrock = require('bedrock');

// load config defaults
require('./config');

exports.notify = async ({
  account, email, authenticationMethod, notification, token
}) => {
  // emit event for another module to handle
  const event = {
    account,
    email,
    token,
    authenticationMethod,
    notification
  };
  await bedrock.events.emit('bedrock-authn-token.notify', event);
};
