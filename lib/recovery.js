/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';
import assert from 'assert-plus';
import {logger} from './logger.js';

/**
 * Sets a recovery email address for an account and optionally notifies the
 * account holder of the change.
 *
 * @param {object} options - The options to use.
 * @param {string} options.accountId - The ID of the account to set the
 *   recovery email for.
 * @param {string} options.recoveryEmail - The recovery email to set.
 * @param {boolean} [options.notify=true] - Set to `true` to notify the account
 *   user, `false` not to.
 *
 * @returns {Promise} - A Promise that resolves once the operation completes.
 */
export async function setRecoveryEmail({
  accountId, recoveryEmail, notify = true
} = {}) {
  assert.string(accountId, 'accountId');
  assert.string(recoveryEmail, 'recoveryEmail');

  // get the old recovery email and record sequence number
  const record = await brAccount.get({id: accountId});
  const oldRecoveryEmail = record.account.recoveryEmail;

  // apply the update
  const account = {...record.account, recoveryEmail};
  await brAccount.update({account, sequence: record.meta.sequence});

  if(notify) {
    const event = {
      account: accountId,
      email: record.account.email,
      oldRecoveryEmail,
      newRecoveryEmail: recoveryEmail
    };

    try {
      await bedrock.events.emit(
        `bedrock-authn-token.recoveryEmail.change`, event);
    } catch(e) {
      logger.error('Failed to notify user of recovery email change.', {
        account: accountId,
        oldRecoveryEmail,
        newRecoveryEmail: recoveryEmail,
        error: e
      });
    }
  }
}
