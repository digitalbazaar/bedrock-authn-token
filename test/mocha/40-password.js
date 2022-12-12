/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as brAuthnToken from '@bedrock/authn-token';
import {mockData} from './mock.data.js';
import {prepareDatabase} from './helpers.js';

describe('Password API', () => {
  describe('set', () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await prepareDatabase(mockData);
    });
    it('should set a password', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      let result;
      let err;
      try {
        const {hash} = await brAuthnToken._pbkdf2.pbkdf2({secret: 'password'});
        result = await brAuthnToken.set({
          accountId,
          type: 'password',
          hash
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.type.should.equal('password');
    });
    it('should throw error if email or account is not given', async () => {
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.message.should.equal(
        'Exactly one of "accountId" or "email" is required.');
    });
    it('should throw error if both email and account is given', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const email = 'someEmail@email.com';
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          accountId,
          type: 'password',
          email
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.message.should.equal(
        'Exactly one of "accountId" or "email" is required.');
    });
  });
  describe('verify', () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await prepareDatabase(mockData);
    });
    it('should verify a valid password', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      // set a password for the account
      const {hash} = await brAuthnToken._pbkdf2.pbkdf2({secret: 'password'});
      const token = await brAuthnToken.set({
        accountId,
        type: 'password',
        hash
      });
      should.exist(token);
      token.should.have.keys(['type', 'id']);
      // getAll password for the account
      let result;
      let err;
      try {
        result = await brAuthnToken.getAll({
          accountId,
          type: 'password'
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.an('object');
      result.tokens.should.be.an('array');
      result.tokens[0].should.have.keys([
        'authenticationMethod', 'requiredAuthenticationMethods', 'id',
        'hashParameters', 'sha256'
      ]);
      // get rehash password using the same parameters
      const {hash: hash2} = await brAuthnToken._pbkdf2.pbkdf2({
        secret: 'password', phc: result.tokens[0].hashParameters
      });
      // verify the password token
      let verifyResult;
      let err2;
      try {
        verifyResult = await brAuthnToken.verify({
          accountId,
          type: 'password',
          hash: hash2
        });
      } catch(e) {
        err2 = e;
      }
      assertNoError(err2);
      should.exist(verifyResult);
      verifyResult.should.eql({
        id: accountId,
        email: 'alpha@example.com',
        token: {type: 'password', authenticationMethod: 'password'}
      });
    });
    it('should return false if a different hash is passed', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      // set a password for the account
      const {hash} = await brAuthnToken._pbkdf2.pbkdf2({secret: 'password'});
      const token = await brAuthnToken.set({
        accountId,
        type: 'password',
        hash
      });
      should.exist(token);
      token.should.have.keys(['type', 'id']);

      // make a different hash
      const {hash: hash2} = await brAuthnToken._pbkdf2.pbkdf2({secret: 'foo'});
      // try to verify the password token (should fail)
      let verifyResult;
      let err;
      try {
        verifyResult = await brAuthnToken.verify({
          accountId,
          type: 'password',
          hash: hash2
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(verifyResult);
      verifyResult.should.equal(false);
    });
  });
});
