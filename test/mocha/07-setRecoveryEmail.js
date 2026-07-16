/*!
 * Copyright (c) 2018-2026 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';
import * as brAuthnToken from '@bedrock/authn-token';
import {mockData} from './mock.data.js';
import {prepareDatabase} from './helpers.js';

describe('setRecoveryEmail API', () => {
  // NOTE: the accounts collection is getting erased before each test
  // this allows for the creation of tokens using the same account info
  beforeEach(async () => {
    await prepareDatabase(mockData);
  });
  it('should set recovery email', async () => {
    const accountId = mockData.accounts['alpha@example.com'].account.id;
    const expectedRecoveryEmail = 'alpha-recovery@example.com';
    let err;
    try {
      await brAuthnToken.setRecoveryEmail({
        accountId,
        recoveryEmail: expectedRecoveryEmail
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);

    const {account} = await brAccount.get({id: accountId});
    should.exist(account);
    const recoveryEmail = account?.recoveryEmail;
    should.exist(recoveryEmail);
    recoveryEmail.should.equal(expectedRecoveryEmail);
  });
  it('should include "requestOrigin" in the recoveryEmail.change event',
    async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const expectedRecoveryEmail = 'alpha-recovery@example.com';
      const events = [];
      const listener = event => events.push(event);
      bedrock.events.on('bedrock-authn-token.recoveryEmail.change', listener);
      try {
        await brAuthnToken.setRecoveryEmail({
          accountId,
          requestOrigin: 'https://wallet.example',
          recoveryEmail: expectedRecoveryEmail
        });
      } finally {
        bedrock.events.removeListener(
          'bedrock-authn-token.recoveryEmail.change',
          listener
        );
      }
      events.length.should.equal(1);
      const [event] = events;
      event.email.should.equal('alpha@example.com');
      event.requestOrigin.should.equal('https://wallet.example');
      event.newRecoveryEmail.should.equal(expectedRecoveryEmail);
    });
});
