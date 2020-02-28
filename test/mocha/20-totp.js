/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brAccount = require('bedrock-account');
const brAuthnToken = require('bedrock-authn-token');
const helpers = require('./helpers.js');
const mockData = require('./mock.data');
const {totp} = require('otplib');

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
    it('should set a secret with a clientId', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      const clientId = 'someWebsite';
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          clientId,
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
      result.otpAuthUrl.startsWith(`otpauth://totp/${clientId}:`)
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
      const totpToken = totp.generate(secret);
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          totpToken,
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
      // an invalid random totpToken string
      const totpToken = '91bc2849-2f43-4847-b5ad-01c0436b3a07';
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          totpToken,
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
      let totpToken = totp.generate(secret);
      let err;
      let result;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          totpToken,
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
      totpToken = totp.generate(secret);
      err = null;
      result = null;
      try {
        result = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'totp',
          totpToken,
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      err.name.should.equal('NotFoundError');
    });
  }); // end delete
}); // end totp api
