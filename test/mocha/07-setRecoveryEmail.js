/*!
 * Copyright (c) 2018-2023 Digital Bazaar, Inc. All rights reserved.
 */
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
});
