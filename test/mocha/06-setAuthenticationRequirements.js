/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as brAccount from '@bedrock/account';
import * as brAuthnToken from '@bedrock/authn-token';
import {prepareDatabase} from './helpers.js';
import {mockData} from './mock.data.js';

describe('setAuthenticationRequirements API', () => {
  // NOTE: the accounts collection is getting erased before each test
  // this allows for the creation of tokens using the same account info
  beforeEach(async () => {
    await prepareDatabase(mockData);
  });
  it('should set required authentication methods', async () => {
    const accountId = mockData.accounts['alpha@example.com'].account.id;
    const requiredAuthenticationMethods = [
      'token-client-registration',
      'login-email-challenge'
    ];
    let err;
    try {
      await brAuthnToken.setAuthenticationRequirements({
        accountId,
        requiredAuthenticationMethods
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);

    const {meta} = await brAccount.get({id: accountId});
    should.exist(meta);
    const methods = meta?.['bedrock-authn-token']
      ?.requiredAuthenticationMethods;
    should.exist(methods);
    methods.should.deep.equal(requiredAuthenticationMethods);
  });
});
