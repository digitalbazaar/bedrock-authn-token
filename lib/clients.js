/*
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const assert = require('assert-plus');
const bedrock = require('bedrock');
const database = require('bedrock-mongodb');
const brPermission = require('bedrock-permission');
const {promisify} = require('util');
const brPermissionCheck = promisify(brPermission.checkPermission);
const {BedrockError} = bedrock.util;
const {prefixedHash} = require('./helpers');

// load config defaults
require('./config');

const logger = require('./logger');

// module API
const api = {};
module.exports = api;

const PERMISSIONS = bedrock.config.permission.permissions;

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
 * @param actor the actor or capabilities to perform the action.
 * @param [account] the ID of the account to add a client for.
 * @param [email] the email address for the account to add a client for.
 * @param clientId an identifier for the client (e.g., a cookie value).
 * @param [authenticated] `true` to indicate the client has been authenticated;
 *   this should happen through the verification of an authentication token
 *   associated with the client.
 * @param [notify=true] `true` to notify the account user, `false` not to.
 *
 * @return a Promise that resolves once the operation completes.
 */
api.set = async ({
  actor, account, email, clientId, authenticated, notify = true
}) => {
  assert.bool(authenticated);
  assert.optionalString(account, 'account');
  assert.optionalString(email, 'email');
  assert.string(clientId, 'clientId');
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }
  if(account && email) {
    throw new Error('Only "account" or "email" must be given.');
  }

  // FIXME: this code is problematic if `account` is not set (likely being
  // skipped when actor is null, but don't have test coverage when it isn't)
  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_UPDATE, {resource: [account]});

  // add/set token client in meta
  const query = {};
  if(account) {
    query.id = database.hash(account);
  } else {
    query['account.email'] = email;
  }
  const key = prefixedHash(clientId);
  const client = {
    id: key,
    // TODO: add more information associated with the client to allow the user
    // to make a decision to remove authenticated client
    authenticated
  };

  let warning = false;
  if(authenticated) {
    // ensure client is not previously registered
    const {registered} = await api.isRegistered(
      {actor, account, email, clientId});
    if(registered) {
      // token was already authenticated! warn user of possible phishing scam
      warning = true;
    }
  }

  if(!warning) {
    const result = await database.collections.account.update(
      query, {
        $set: {
          [`meta.bedrock-authn-token.clients.${key}`]: client
        }
      }, database.writeOptions);
    if(result.result.n === 0) {
      throw new BedrockError(
        'Could not set account token client. Account not found.',
        'NotFoundError', {httpStatusCode: 404, public: true});
    }
  }

  if(notify) {
    const event = {
      type: warning ? 'warning' : (authenticated ? 'authenticated' : 'created'),
      actor,
      account,
      email,
      clientKey: key
    };

    try {
      await bedrock.events.emit(
        `bedrock-authn-token.client.${event.type}`, event);
    } catch(e) {
      logger.error('Failed to notify user of token client event.', {
        account,
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
};

/**
 * Returns whether or not a token client has been registered for the given
 * account or email address.
 *
 * @param actor the actor or capabilities to perform the action.
 * @param [account] the ID of the account.
 * @param [email] the email of the account.
 * @param clientId an identifier for the client (e.g., a cookie value).
 *
 * @return a Promise that resolves to {registered: true|false}.
 */
api.isRegistered = async ({actor, account, email, clientId}) => {
  assert.optionalString(account, 'account');
  assert.optionalString(account, 'email');
  if(!(account || email)) {
    throw new Error('Either "account" or "email" must be provided.');
  }

  await brPermissionCheck(
    actor, PERMISSIONS.ACCOUNT_ACCESS, {resource: [account]});

  // get token from meta
  const key = prefixedHash(clientId);
  const clientKey = `meta.bedrock-authn-token.clients.${key}`;
  const query = {[clientKey]: {id: key, authenticated: true}};
  if(account) {
    query.id = database.hash(account);
  } else {
    query['account.email'] = email;
  }
  const record = await database.collections.account.findOne(
    query, {_id: 0, [clientKey]: 1});
  return {registered: !!record};
};

// TODO: implement getting/removing token clients
