/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brAccount = require('bedrock-account');
const brAuthnToken = require('bedrock-authn-token');
const {prepareDatabase} = require('./helpers.js');
const mockData = require('./mock.data');
const sinon = require('sinon');
const bcrypt = require('bcrypt');

describe('Nonce API', () => {
  describe('set', () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await prepareDatabase(mockData);
    });
    it('should set a challenge', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.type.should.equal('nonce');
      should.exist(result.challenge);
      result.challenge.should.be.a('string');
    });
    it('should set a challenge of length 9 if "typeOptions" is not given',
      async () => {
        const accountId = mockData.accounts['alpha@example.com'].account.id;
        const actor = await brAccount.getCapabilities({id: accountId});
        let result;
        let err;
        try {
          result = await brAuthnToken.set({
            account: accountId,
            actor,
            type: 'nonce',
          });
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.an('object');
        result.should.have.keys(['type', 'id', 'challenge']);
        result.challenge.should.be.a('string');
        result.challenge.should.match(/^\d{9}$/);
      });
    it('should set a challenge of length 9 if "typeOptions.entryStyle" is ' +
      'set to "human"',
    async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
          typeOptions: {entryStyle: 'human'}
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.an('object');
      result.should.have.keys(['type', 'id', 'challenge']);
      result.challenge.should.be.a('string');
      result.challenge.should.match(/^\d{9}$/);
    });
    it('should set a challenge of length 23 if "typeOptions.entryStyle" is ' +
      'set to "machine"',
    async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
          typeOptions: {entryStyle: 'machine'}
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.an('object');
      result.should.have.keys(['type', 'id', 'challenge']);
      result.challenge.should.be.a('string');
      result.challenge.should.match(/^[A-Za-z0-9]{23}$/);
    });
    it('should throw error if "typeOptions.entryStyle" is neither "human" ' +
      'nor "machine"',
    async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
          typeOptions: {entryStyle: 'not-machine-or-human'}
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.message.should.equal('Invalid "entryStyle" "not-machine-or-human"; ' +
        '"entryStyle" must be "human" or "machine".');
    });
    it('should generate an array of nonce', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let err;
      // create three new nonce tokens
      const nonce1 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      const nonce2 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      const nonce3 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      let result;
      try {
        result = await brAuthnToken.getAll({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      should.exist(nonce1);
      should.exist(nonce2);
      should.exist(nonce3);
      should.exist(result);
      result.should.be.an('object');
      result.tokens.should.be.an('array');
      result.tokens.length.should.equal(3);
    });
    it('should throw error if email or account is not given', async () => {
      const accountId = '';
      const actor = await brAccount.getCapabilities({id: accountId});
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.message.should.equal('Either "account" or "email" must be provided.');
    });
    it('should throw error if both email and account is given', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const email = 'someEmail@email.com';
      const actor = await brAccount.getCapabilities({id: accountId});
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
          email
        });
      } catch(e) {
        err = e;
      }
      should.exist(err);
      should.not.exist(result);
      err.message.should.equal('Only "account" or "email" must be given.');
    });
    it('should throw error if maxNonceCount is  greater than 5', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let err;
      // create five nonce tokens
      const nonce1 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      const nonce2 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      const nonce3 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      const nonce4 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      should.exist(nonce1);
      should.exist(nonce2);
      should.exist(nonce3);
      should.exist(nonce4);
      let nonce5;
      try {
        nonce5 = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      should.exist(nonce5);
      should.not.exist(err);
      // try to create another nonce token when other 5 nonces hasn't expired
      // it should throw an error.
      let nonce6;
      try {
        nonce6 = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(nonce6);
      should.exist(err);
      err.name.should.equal('NotAllowedError');
      err.message.should.equal('Tokens exceeds maxNonceCount of 5.');
    });
    it('should get a nonce with an "id"', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      // create two nonces
      const nonce1 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      should.exist(nonce1);
      nonce1.should.have.keys(['challenge', 'id', 'type']);
      nonce1.type.should.equal('nonce');
      const nonce2 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      should.exist(nonce2);
      nonce2.should.have.keys(['challenge', 'id', 'type']);
      nonce2.type.should.equal('nonce');
      // get nonce1 using its id, the result of get should have the same id as
      // nonce1
      const result = await brAuthnToken.get({
        account: accountId,
        actor,
        type: 'nonce',
        id: nonce1.id
      });
      should.exist(result);
      result.id.should.equal(nonce1.id);
    });
  });
  describe('verify', () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await prepareDatabase(mockData);
    });
    it('should verify a valid nonce', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      // set a nonce for the account
      const nonce = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      should.exist(nonce);
      nonce.should.have.keys(['type', 'id', 'challenge']);
      // getAll nonce for the account
      let result;
      let err;
      try {
        result = await brAuthnToken.getAll({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result);
      result.should.be.an('object');
      result.tokens.should.be.an('array');
      result.tokens[0].should.have.keys([
        'authenticationMethod', 'requiredAuthenticationMethods', 'id', 'salt',
        'sha256', 'expires'
      ]);
      // get challenge from nonce and hash it using the same salt
      const challenge = nonce.challenge;
      const hash = await bcrypt.hash(challenge, result.tokens[0].salt);
      // verify the nonce token
      let verifyResult;
      let err2;
      try {
        verifyResult = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'nonce',
          challenge,
          hash
        });
      } catch(e) {
        err2 = e;
      }
      assertNoError(err2);
      should.exist(verifyResult);
      verifyResult.should.eql({
        id: accountId,
        email: 'alpha@example.com',
        token: {type: 'nonce', authenticationMethod: 'nonce'}
      });
    });
    it('should return false if a different hash is passed', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      // set a nonce for the account
      const nonce = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      should.exist(nonce);
      nonce.should.have.keys(['type', 'id', 'challenge']);

      const challenge = nonce.challenge;
      // make a different hash
      const hash = await bcrypt.hash(challenge, 10);
      // verify the nonce token
      let verifyResult;
      let err;
      try {
        verifyResult = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'nonce',
          challenge,
          hash
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(verifyResult);
      verifyResult.should.equal(false);
    });
    it('should throw error when verifying nonce that has expired', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      // set a nonce with an older date.
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const clock = sinon.useFakeTimers(yesterday.getTime());

      let err;
      let nonce;
      try {
        nonce = await brAuthnToken.set({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(nonce);
      nonce.should.have.keys(['type', 'id', 'challenge']);

      // getAll nonce for the account
      let result;
      let err2;
      try {
        result = await brAuthnToken.getAll({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err2 = e;
      }
      assertNoError(err2);
      should.exist(result);
      result.should.be.an('object');
      result.tokens.should.be.an('array');
      result.tokens[0].should.have.keys([
        'authenticationMethod', 'requiredAuthenticationMethods', 'id', 'salt',
        'sha256', 'expires'
      ]);

      // undo the stub
      clock.restore();

      // get challenge from nonce and hash it using the same salt
      const challenge = nonce.challenge;
      const hash = await bcrypt.hash(challenge, result.tokens[0].salt);

      // verify the nonce token
      let verifyResult;
      let err3;
      try {
        verifyResult = await brAuthnToken.verify({
          account: accountId,
          actor,
          type: 'nonce',
          challenge,
          hash
        });
      } catch(e) {
        err3 = e;
      }
      should.not.exist(verifyResult);
      should.exist(err3);
      err3.name.should.equal('NotFoundError');
      err3.message.should.equal('Authentication token has expired.');
    });
  });
});
describe('Remove expired nonce', () => {
  // NOTE: the accounts collection is getting erased before each test
  // this allows for the creation of tokens using the same account info
  beforeEach(async () => {
    await prepareDatabase(mockData);
  });
  it('should remove an expired nonce', async () => {
    const accountId = mockData.accounts['alpha@example.com'].account.id;
    const actor = await brAccount.getCapabilities({id: accountId});
    // set a token with an older date.
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const clock = sinon.useFakeTimers(yesterday.getTime());
    let nonce1;
    let err;
    try {
      nonce1 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(nonce1);
    // get all existing nonce for the account, it should give exactly one
    let result1;
    try {
      result1 = await brAuthnToken.getAll({
        account: accountId,
        actor,
        type: 'nonce',
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result1);
    result1.should.be.an('object');
    result1.tokens.should.be.an('array');
    result1.tokens[0].should.have.keys([
      'authenticationMethod', 'requiredAuthenticationMethods', 'id', 'salt',
      'sha256', 'expires'
    ]);
    // undo the stub
    clock.restore();
    // get all existing nonce for the same account again after undoing the stub,
    // it should give an empty array as getAll drops any expired token.
    let result2;
    try {
      result2 = await brAuthnToken.getAll({
        account: accountId,
        actor,
        type: 'nonce',
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(result2);
    result2.should.be.an('object');
    result2.tokens.should.eql([]);
  });
});
