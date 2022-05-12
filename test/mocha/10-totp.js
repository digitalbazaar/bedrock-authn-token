/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as brAuthnToken from '@bedrock/authn-token';
import * as helpers from './helpers.js';
import {authenticator} from 'otplib';
import {mockData} from './mock.data.js';

describe('TOTP API', () => {
  describe('set', () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await helpers.prepareDatabase(mockData);
    });
    it('should set a secret', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      let result;
      let err;
      try {
        result = await brAuthnToken.set({accountId, type: 'totp'});
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
      const serviceId = 'someWebsite';
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          accountId,
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
      await brAuthnToken.set({
        accountId,
        type: 'totp'
      });
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          accountId,
          type: 'totp'
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(result);
      should.exist(err);
    });
    it('should throw error if `accountId` is not non-nonce type',
      async () => {
        let result;
        let err;
        try {
          result = await brAuthnToken.set({
            type: 'totp',
            email: 'alpha@example.com'
          });
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.message.should.equal('accountId (string) is required');
      });
  }); // end set

  describe('verify', () => {
    const mockAccountEmail = 'alpha@example.com';
    let secret;
    let accountId;
    before(async () => {
      await helpers.prepareDatabase(mockData);
    });
    // set an OTOP secret
    before(async () => {
      accountId = mockData.accounts[mockAccountEmail].account.id;
      ({secret} = await brAuthnToken.set({
        accountId,
        type: 'totp',
      }));
    });
    it('should verify a valid token', async () => {
      const challenge = authenticator.generate(secret);
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          accountId,
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
          accountId,
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
    before(async () => {
      await helpers.prepareDatabase(mockData);
    });
    // set an OTOP secret
    before(async () => {
      accountId = mockData.accounts[mockAccountEmail].account.id;
      ({secret} = await brAuthnToken.set({
        accountId,
        type: 'totp',
      }));
    });
    it('should delete a secret', async () => {
      let challenge = authenticator.generate(secret);
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          accountId,
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
          accountId,
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
          accountId,
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
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await helpers.prepareDatabase(mockData);
      accountId = mockData.accounts['alpha@example.com'].account.id;
      const accountId2 = mockData.accounts['beta@example.com'].account.id;

      // creates token
      await brAuthnToken.set({
        accountId,
        type: 'totp'
      });
      // second token is created here in order to do proper assertions for
      // 'nReturned', 'totalKeysExamined' and 'totalDocsExamined'.
      await brAuthnToken.set({
        accountId: accountId2,
        type: 'totp'
      });
    });
    describe('setToken() for set()', () => {
      it(`is properly indexed for 'id' in setToken()`, async () => {
        const accountId3 = mockData.accounts['gamma@example.com'].account.id;
        const {executionStats} = await brAuthnToken._tokenStorage.setToken({
          accountId: accountId3,
          type: 'totp',
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
    });
    describe('getAccountRecord() for get()', () => {
      it(`is properly indexed for 'id'`, async () => {
        const {
          executionStats
        } = await brAuthnToken._tokenStorage.getAccountRecord({
          accountId,
          type: 'totp',
          // token must exist
          requireToken: true,
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
      it(`is properly indexed for 'account.email'`, async () => {
        const {
          executionStats
        } = await brAuthnToken._tokenStorage.getAccountRecord({
          email: 'alpha@example.com',
          type: 'totp',
          // token must exist
          requireToken: true,
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
    });
    describe('getAccountRecord() for getAll()', () => {
      it(`is properly indexed for 'id'`, async () => {
        const {
          executionStats
        } = await brAuthnToken._tokenStorage.getAccountRecord({
          accountId,
          type: 'totp',
          // getAll
          requireToken: false,
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
      it(`is properly indexed for 'account.email'`, async () => {
        const {
          executionStats
        } = await brAuthnToken._tokenStorage.getAccountRecord({
          email: 'alpha@example.com',
          type: 'totp',
          // getAll
          requireToken: false,
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
    });
    describe('removeToken() for remove()', () => {
      it(`is properly indexed for 'id'`, async () => {
        const {executionStats} = await brAuthnToken._tokenStorage.removeToken({
          accountId,
          type: 'totp',
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
    });
    describe('getAccountRecord() for verify()', () => {
      it(`is properly indexed for 'id'`, async () => {
        const {
          executionStats
        } = await brAuthnToken._tokenStorage.getAccountRecord({
          accountId,
          type: 'totp',
          // token must exist
          requiredToken: true,
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
      it(`is properly indexed for 'account.email'`, async () => {
        const {
          executionStats
        } = await brAuthnToken._tokenStorage.getAccountRecord({
          email: 'alpha@example.com',
          type: 'totp',
          // token must exist
          requiredToken: true,
          explain: true
        });
        executionStats.nReturned.should.equal(1);
        executionStats.totalKeysExamined.should.equal(1);
        executionStats.totalDocsExamined.should.equal(1);
        executionStats.executionStages.inputStage.inputStage.inputStage.stage
          .should.equal('IXSCAN');
      });
    });
    it(`is properly indexed for 'id' in setAuthenticationRequirements()`,
      async () => {
        const requiredAuthenticationMethods = [];
        const {executionStats} = await brAuthnToken
          .setAuthenticationRequirements({
            accountId,
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
