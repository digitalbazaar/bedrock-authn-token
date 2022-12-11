/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';
import assert from 'assert-plus';
import {fastHash} from './helpers.js';
import {logger} from './logger.js';

const {BedrockError} = bedrock.util;

// load config defaults
import './config.js';

/**
 * An object containing information on the query plan.
 *
 * @typedef {object} ExplainObject
 */

/**
 * Sets a token client, i.e., a client that may submit tokens, for an account.
 *
 * In an effort to help prevent phishing, an application may require clients
 * that submit authentication tokens such as email tokens or passwords to
 * first be authenticated themselves. This authentication may happen by, for
 * example, having a user follow an email link using the client that is to be
 * authenticated.
 *
 * If the client includes, for example, a cookie that can be stored prior to
 * following the link as an identifier for that client, then once the user
 * follows the link using the same client that client can be marked as
 * authenticated. If the user was attempting to authenticate via a phishing
 * website that acts as a MitM attacker, the cookie would not be available to
 * that phishing site. Neither would the user be able to register the phishing
 * site's client when following an email link that takes them to the real site.
 *
 * Authentication flows that use this feature should work like this:
 * 1. User visits website and submits their email address and cookie.
 * 2. Website backend calls set() a token client ID based on the cookie
 *    value with the `authenticated` flag set to `false`.
 * 3. Website emails the user a link that they must open in the client.
 * 4. User follows the link in their client and clicks "Allow"/"Register" to
 *    authenticate the client and allow it to be used to send authentication
 *    tokens to login in the future.
 * 5. Website hits its backend to call set(), this time with `authenticated`
 *    set to `true`.
 * 6. Website sends an email informing the user that a new device registered.
 *
 * @param {object} options - The options to use.
 * @param {string} [options.accountId] - The ID of the account to add a client
 *   for.
 * @param {string} [options.email] - The email address for the account to add
 *   a client for.
 * @param {string} options.clientId - An identifier for the client
 *   (e.g., a cookie value).
 * @param {boolean} [options.authenticated] - Set to `true` to indicate the
 *   client has been authenticated; this should happen through the verification
 *   of an authentication token associated with the client.
 * @param {boolean} [options.notify=true] - Set to `true` to notify the account
 *   user, `false` not to.
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise | ExplainObject} - Returns a Promise that resolves once
 *   the operation completes or an ExplainObject if `explain=true`.
 */
export async function set({
  accountId, email, clientId, authenticated, notify = true, explain = false
} = {}) {
  assert.bool(authenticated, 'authenticated');
  assert.optionalString(accountId, 'accountId');
  assert.optionalString(email, 'email');
  assert.string(clientId, 'clientId');
  if(!(accountId || email) || (accountId && email)) {
    throw new Error('Exactly one of "accountId" or "email" is required.');
  }

  // add/set token client in meta
  const query = {};
  if(accountId) {
    query.id = database.hash(accountId);
  } else {
    query['account.email'] = email;
  }

  const key = fastHash({data: clientId, encoding: 'base64'});
  const client = {
    id: key,
    authenticated
  };

  let warning = false;
  if(authenticated) {
    // ensure client is not previously registered
    const {registered} = await isRegistered({accountId, email, clientId});
    if(registered) {
      // token was already authenticated! warn user of possible phishing scam
      warning = true;
    }
  }

  if(explain) {
    // 'find()' is used here because 'updateMany()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(query);
    return cursor.explain('executionStats');
  }

  if(!warning) {
    const result = await database.collections.account.updateOne(
      query, {
        $set: {
          [`meta.bedrock-authn-token.clients.${key}`]: client
        }
      });
    if(result.result.n === 0) {
      throw new BedrockError(
        'Could not set account token client. Account not found.',
        'NotFoundError', {httpStatusCode: 404, public: true});
    }
  }

  if(notify) {
    const event = {
      type: warning ? 'warning' : (authenticated ? 'authenticated' : 'created'),
      account: accountId,
      email,
      clientKey: key
    };

    try {
      await bedrock.events.emit(
        `bedrock-authn-token.client.${event.type}`, event);
    } catch(e) {
      logger.error('Failed to notify user of token client event.', {
        account: accountId,
        email,
        type: event.type,
        error: e
      });
    }
  }

  if(warning) {
    throw new BedrockError(
      'Could not set account token client as authenticated; token client ' +
      'already authenticated.',
      'DuplicateError', {httpStatusCode: 400, public: true});
  }
}

/**
 * Returns whether or not a token client has been registered for the given
 * account or email address.
 *
 * @param {object} options - The options to use.
 * @param {string} [options.accountId] - The ID of the account.
 * @param {string} [options.email] - The email of the account.
 * @param {string} options.clientId - An identifier for the client
 *   (e.g., a cookie value).
 * @param {boolean} [options.explain=false] - An optional explain boolean.
 *
 * @returns {Promise<object> | ExplainObject} - Returns a Promise that resolves
 *   to {registered: true|false} or an ExplainObject if `explain=true`.
 */
export async function isRegistered({
  accountId, email, clientId, explain = false
} = {}) {
  assert.optionalString(accountId, 'accountId');
  assert.optionalString(email, 'email');
  if(!(accountId || email)) {
    throw new Error('Either "accountId" or "email" is required.');
  }

  // get token from meta
  const key = fastHash({data: clientId, encoding: 'base64'});
  const clientKey = `meta.bedrock-authn-token.clients.${key}`;
  const query = {[clientKey]: {id: key, authenticated: true}};
  const projection = {_id: 0, [clientKey]: 1};
  if(accountId) {
    query.id = database.hash(accountId);
  } else {
    query['account.email'] = email;
  }

  if(explain) {
    // 'find().limit(1)' is used here because 'findOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(
      query, {projection}).limit(1);
    return cursor.explain('executionStats');
  }

  const record = await database.collections.account.findOne(
    query, {projection});
  return {registered: !!record};
}
