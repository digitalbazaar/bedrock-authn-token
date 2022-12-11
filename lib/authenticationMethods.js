/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';
import assert from 'assert-plus';

const {config, util: {BedrockError}} = bedrock;

bedrock.events.on('bedrock-account.insert', ({meta}) => {
  // get default `requiredAuthenticationMethods`
  const {'authn-token': cfg} = config;
  if(cfg.defaultRequiredAuthenticationMethods.length === 0) {
    // no defaults
    return;
  }

  // set default `requiredAuthenticationMethods` if none already set on account
  let brAuthnTokenMeta = meta['bedrock-authn-token'];
  if(!brAuthnTokenMeta) {
    brAuthnTokenMeta = meta['bedrock-authn-token'] = {};
  }
  if(!brAuthnTokenMeta.requiredAuthenticationMethods) {
    brAuthnTokenMeta.requiredAuthenticationMethods =
      cfg.defaultRequiredAuthenticationMethods.slice();
  }
});

/**
 * Sets required authentication methods for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} options.accountId - The ID of the account.
 * @param {Array} options.requiredAuthenticationMethods - An optional,
 *   application specific set of authentication methods (specified by ID)
 *   that must first be satisfied before this token can be verified.
 *
 * @returns {Promise} - Returns a Promise that resolves once the operation
 *   completes.
 */
export async function setAuthenticationRequirements({
  accountId, requiredAuthenticationMethods
} = {}) {
  assert.string(accountId, 'accountId');
  assert.array(requiredAuthenticationMethods, 'requiredAuthenticationMethods');

  try {
    // get existing record meta
    const record = await brAccount.get({id: accountId});

    // add required authentication methods to meta
    const meta = {
      ...record.meta,
      sequence: record.meta.sequence + 1
    };
    if(!meta['bedrock-authn-token']) {
      meta['bedrock-authn-token'] = {requiredAuthenticationMethods};
    } else {
      meta['bedrock-authn-token'].requiredAuthenticationMethods =
        requiredAuthenticationMethods;
    }
    await brAccount.update({id: accountId, meta});
  } catch(e) {
    // determine if account does not exist
    const notFound = e.name === 'NotFoundError' ||
      !await brAccount.exists({id: accountId});
    throw new BedrockError(
      'Could not set account required authentication methods.' +
      notFound ? ' Account not found.' : '', {
        name: notFound ? 'NotFoundError' : 'OperationError',
        details: {httpStatusCode: notFound ? 404 : 500, public: true},
        cause: e
      });
  }
}

/**
 * Gets required authentication methods for an account.
 *
 * @param {object} options - The options to use.
 * @param {string} options.accountId - The ID of the account.
 *
 * @returns {Promise} - A Promise that resolves to
 *   {requiredAuthenticationMethods}.
 */
export async function getAuthenticationRequirements({accountId} = {}) {
  assert.string(accountId, 'accountId');

  const {meta} = await brAccount.get({id: accountId});
  const data = meta['bedrock-authn-token'] || {};
  const {requiredAuthenticationMethods = []} = data;

  return {requiredAuthenticationMethods};
}

/**
 * Checks if the given authenticated methods meet the given required
 * authentication methods.
 *
 * @param {object} options - The options to use.
 * @param {Array} options.requiredAuthenticationMethods - The required
 *   authentication methods.
 * @param {Array} options.authenticatedMethods - The authenticated methods.
 *
 * @returns {Promise<boolean>} - A Promise that resolves to `true` if met,
 *   `false` if not.
 */
export async function checkAuthenticationRequirements({
  requiredAuthenticationMethods, authenticatedMethods
} = {}) {
  assert.array(requiredAuthenticationMethods, 'requiredAuthenticationMethods');

  // each element in `requiredAuthenticationMethods` may be either a single
  // string or an array of strings where each string identifies an
  // authentication method; an array of strings indicates choice: any one of
  // the identifiers may be used to fulfill that dependency
  // Note: Code assumes no degenerative cases exist where
  // `requiredAuthenticationMethods` expresses an OR condition that includes a
  // method that is listed in two places; no method should be "equivalent" for
  // two different factors, will "fail closed" if this assumption is invalid
  const unmet = requiredAuthenticationMethods.slice();
  for(const m of authenticatedMethods) {
    for(const [i, d] of unmet.entries()) {
      const match = Array.isArray(d) ? m => d.includes(m) : m => d === m;
      if(match(m)) {
        unmet.splice(i, 1);
        break;
      }
    }
  }
  return unmet.length === 0;
}
