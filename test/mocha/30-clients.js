/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as brAuthnToken from '@bedrock/authn-token';
import * as helpers from './helpers.js';
import {mockData} from './mock.data.js';

describe('clients', () => {
  let accountId;
  let accountId2;
  // NOTE: the accounts collection is getting erased before each test
  // this allows for the creation of tokens using the same account info
  beforeEach(async () => {
    await helpers.prepareDatabase(mockData);
    accountId = mockData.accounts['alpha@example.com'].account.id;
    accountId2 = mockData.accounts['beta@example.com'].account.id;

    await brAuthnToken.clients.set({
      accountId,
      clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
      authenticated: true
    });
  });
  it('should check is registered via "id"', async () => {
    const {registered} = await brAuthnToken.clients.isRegistered({
      accountId,
      clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be'
    });
    should.exist(registered);
    registered.should.equal(true);
  });
  it('should check is registered via "email"', async () => {
    const {registered} = await brAuthnToken.clients.isRegistered({
      email: 'alpha@example.com',
      clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be'
    });
    should.exist(registered);
    registered.should.equal(true);
  });
  it('should check is NOT registered for mismatched client ID', async () => {
    const {registered} = await brAuthnToken.clients.isRegistered({
      accountId,
      clientId: 'does not exist'
    });
    should.exist(registered);
    registered.should.equal(false);
  });
  it('should check is NOT registered via "id"', async () => {
    const {registered} = await brAuthnToken.clients.isRegistered({
      accountId: accountId2,
      clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be'
    });
    should.exist(registered);
    registered.should.equal(false);
  });
  it('should check is NOT registered via "email"', async () => {
    const {registered} = await brAuthnToken.clients.isRegistered({
      email: 'beta@example.com',
      clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be'
    });
    should.exist(registered);
    registered.should.equal(false);
  });
  it('should check is NOT registered via "id" (non-existent)', async () => {
    const {registered} = await brAuthnToken.clients.isRegistered({
      accountId: 'doesnotexist',
      clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be'
    });
    should.exist(registered);
    registered.should.equal(false);
  });
  it('should check is NOT registered via "email" (non-existant)', async () => {
    const {registered} = await brAuthnToken.clients.isRegistered({
      email: 'doesnotexist@example.com',
      clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be'
    });
    should.exist(registered);
    registered.should.equal(false);
  });
});
