/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brAccount = require('bedrock-account');
const brAuthnToken = require('bedrock-authn-token');
const helpers = require('./helpers.js');
const mockData = require('./mock.data');
const {authenticator} = require('otplib');

describe('TOTP API', () => {
  describe('set', () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await helpers.prepareDatabase(mockData);
    });
    it('should set a secret', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'totp',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.type.should.equal('totp');
      should.exist(result.secret);
      result.secret.should.be.a('string');
      should.exist(result.otpAuthUrl);
      result.otpAuthUrl.should.be.a('string');
      result.otpAuthUrl.startsWith('otpauth://totp/').should.be.true;
    });
    it('should set a secret with a serviceId', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      const serviceId = 'someWebsite';
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          serviceId,
          type: 'totp',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.type.should.equal('totp');
      should.exist(result.secret);
      result.secret.should.be.a('string');
      should.exist(result.otpAuthUrl);
      result.otpAuthUrl.should.be.a('string');
      result.otpAuthUrl.startsWith(`otpauth://totp/${serviceId}:`)
        .should.be.true;
    });
    it('should not set a secret if one already exists', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'totp',
      });
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'totp',
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
    });
    it('should throw error if account is not given for types except nonce',
      async () => {
        const accountId = mockData.accounts['alpha@example.com'].account.id;
        const actor = await brAccount.getCapabilities({id: accountId});
        let result;
        let err;
        try {
          result = await brAuthnToken.set({
            actor,
            type: 'totp',
            email: 'alpha@example.com'
          });
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.message.should.equal('account (string) is required');
      });
  }); // end set

  describe('verify', () => {
    const mockAccountEmail = 'alpha@example.com';
    let secret;
    let accountId;
    let actor;
    before(async () => {
      await helpers.prepareDatabase(mockData);
    });
    // set an OTOP secret
    before(async () => {
      accountId = mockData.accounts[mockAccountEmail].account.id;
      actor = await brAccount.getCapabilities({id: accountId});
      ({secret} = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'totp',
      }));
    });
    it('should verify a valid token', async () => {
      const challenge = authenticator.generate(secret);
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          challenge,
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.eql({
        id: accountId,
        email: mockAccountEmail,
        token: {type: 'totp', authenticationMethod: 'totp'}
      });
    });
    it('should not verify an invalid token', async () => {
      // an invalid random challenge string
      const challenge = '91bc2849-2f43-4847-b5ad-01c0436b3a07';
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          challenge,
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.a('boolean');
      result.should.be.false;
    });
  }); // end verify

  describe('delete', () => {
    const mockAccountEmail = 'alpha@example.com';
    let secret;
    let accountId;
    let actor;
    before(async () => {
      await helpers.prepareDatabase(mockData);
    });
    // set an OTOP secret
    before(async () => {
      accountId = mockData.accounts[mockAccountEmail].account.id;
      actor = await brAccount.getCapabilities({id: accountId});
      ({secret} = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'totp',
      }));
    });
    it('should delete a secret', async () => {
      let challenge = authenticator.generate(secret);
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          challenge,
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.eql({
        id: accountId,
        email: mockAccountEmail,
        token: {type: 'totp', authenticationMethod: 'totp'}
      });

      err = null;
      result = null;
      try {
        result = await brAuthnToken.remove({
          account: accountId,
          actor,
          type: 'totp',
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(err);

      // attempt to validate the TOTP token again
      challenge = authenticator.generate(secret);
      err = null;
      result = null;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          challenge,
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('NotFoundError');
    });
  }); // end delete
}); // end totp api

describe('TOTP Database Tests', () => {
  describe('Indexes', async () => {
    let accountId;
    let actor;
    let secret;
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await helpers.prepareDatabase(mockData);
      accountId = mockData.accounts['alpha@example.com'].account.id;
      actor = await brAccount.getCapabilities({id: accountId});
      const accountId2 = mockData.accounts['beta@example.com'].account.id;
      const actor2 = await brAccount.getCapabilities({id: accountId2});

      // creates tokens
      ({secret} = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'totp'
      }));
      await brAuthnToken.set({
        account: accountId2,
        actor: actor2,
        type: 'totp'
      });
    });
    it(`is properly indexed for 'id' in set()`, async () => {
      const accountId3 = mockData.accounts['gamma@example.com'].account.id;
      const actor3 = await brAccount.getCapabilities({id: accountId3});
      const {executionStats} = await brAuthnToken.set({
        account: accountId3,
        actor: actor3,
        type: 'totp',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'id' in get()`, async () => {
      const {executionStats} = await brAuthnToken.get({
        account: accountId,
        actor,
        type: 'totp',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'account.email' in get()`, async () => {
      const {executionStats} = await brAuthnToken.get({
        email: 'alpha@example.com',
        actor,
        type: 'totp',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'id' in getAll()`, async () => {
      const {executionStats} = await brAuthnToken.getAll({
        account: accountId,
        actor,
        type: 'totp',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'account.email' in getAll()`, async () => {
      const {executionStats} = await brAuthnToken.getAll({
        email: 'alpha@example.com',
        actor,
        type: 'totp',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'id' in remove()`, async () => {
      const {executionStats} = await brAuthnToken.remove({
        account: accountId,
        actor,
        type: 'totp',
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'id' in verify()`, async () => {
      const challenge = authenticator.generate(secret);
      const {executionStats} = await brAuthnToken.verify({
        account: accountId,
        actor,
        type: 'totp',
        challenge,
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'account.email' in verify()`, async () => {
      const challenge = authenticator.generate(secret);
      const {executionStats} = await brAuthnToken.verify({
        email: 'alpha@example.com',
        actor,
        type: 'totp',
        challenge,
        explain: true
      });
      executionStats.nReturned.should.equal(1);
      executionStats.totalKeysExamined.should.equal(1);
      executionStats.totalDocsExamined.should.equal(1);
      executionStats.executionStages.inputStage.inputStage.inputStage.stage
        .should.equal('IXSCAN');
    });
    it(`is properly indexed for 'id' in setAuthenticationRequirements()`,
      async () => {
        const requiredAuthenticationMethods = [];
        const {executionStats} = await brAuthnToken
          .setAuthenticationRequirements({
            account: accountId,
            actor,
            requiredAuthenticationMethods,
            explain: true
          });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
  });
});
