/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import '@bedrock/account';

// load config defaults
import './config.js';

export async function notify({
  account, email, authenticationMethod, notification, token
}) {
  // emit event for another module to handle
  const event = {
    account,
    email,
    token,
    authenticationMethod,
    notification
  };
  await bedrock.events.emit('bedrock-authn-token.notify', event);
}
