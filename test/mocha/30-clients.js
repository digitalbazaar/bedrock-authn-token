/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brAccount = require('bedrock-account');
const brAuthnToken = require('bedrock-authn-token');
const helpers = require('./helpers.js');
const mockData = require('./mock.data');

describe('Clients Database Tests', () => {
  describe('Indexes', async () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await helpers.prepareDatabase(mockData);
    });
    it(`is properly indexed for 'id' in set()`, async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      const {executionStats} = await brAuthnToken.clients.set({
        account: accountId,
        actor,
        clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
        authenticated: true,
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'account.email' in set()`, async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      const {executionStats} = await brAuthnToken.clients.set({
        email: 'alpha@example.com',
        actor,
        clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
        authenticated: true,
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'id' and ` +
      `'meta.bedrock-authn-token.clients.{key}' in ` +
      'isRegistered()', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});

      await brAuthnToken.clients.set({
        account: accountId,
        actor,
        clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
        authenticated: true
      });

      const {executionStats} = await brAuthnToken.clients.isRegistered({
        account: accountId,
        actor,
        clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'account.email' and ` +
      `'meta.bedrock-authn-token.clients.{key}' in ` +
      'isRegistered()', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});

      await brAuthnToken.clients.set({
        account: accountId,
        actor,
        clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
        authenticated: true
      });

      const {executionStats} = await brAuthnToken.clients.isRegistered({
        email: 'alpha@example.com',
        actor,
        clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
  });
});
