/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as brAuthnToken from '@bedrock/authn-token';
import * as helpers from './helpers.js';
import {mockData} from './mock.data.js';

describe('Clients Database Tests', () => {
  describe('Indexes', async () => {
    let accountId;
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await helpers.prepareDatabase(mockData);
      accountId = mockData.accounts['alpha@example.com'].account.id;
      const accountId2 = mockData.accounts['beta@example.com'].account.id;

      await brAuthnToken.clients.set({
        accountId,
        clientId: '670753bd-2cf3-4878-8de4-4aa5e28989be',
        authenticated: true
      });

      // second client is created here in order to do proper assertions for
      // 'nReturned', 'totalKeysExamined' and 'totalDocsExamined'.
      await brAuthnToken.clients.set({
        accountId: accountId2,
        clientId: 'd55d8879-6d01-472e-84a7-eb22ebf319e5',
        authenticated: true
      });
    });
    it(`is properly indexed for 'id' in set()`, async () => {
      const accountId3 = mockData.accounts['gamma@example.com'].account.id;
      const {executionStats} = await brAuthnToken.clients.set({
        accountId: accountId3,
        clientId: '4ce0fe94-8478-469e-a4df-08b42acdaf72',
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
      const {executionStats} = await brAuthnToken.clients.set({
        email: 'gamma@example.com',
        clientId: '4ce0fe94-8478-469e-a4df-08b42acdaf72',
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
      const {executionStats} = await brAuthnToken.clients.isRegistered({
        accountId,
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
      const {executionStats} = await brAuthnToken.clients.isRegistered({
        email: 'alpha@example.com',
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
