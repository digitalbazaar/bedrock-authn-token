/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brAccount = require('bedrock-account');
const brAuthnToken = require('bedrock-authn-token');
const {prepareDatabase} = require('./helpers.js');
const mockData = require('./mock.data');
const sinon = require('sinon');

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
      result.should.be.an('array');
      result.length.should.equal(3);
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
      err.message.should.equal('Existing tokens exceeds maxNonceCount of 5.');
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
    const dateStub = sinon.stub(Date, 'now').callsFake(() => {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      return yesterday;
    });
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
    // undo the stub
    dateStub.restore();
    let result1;
    // get all existing nonce for the account, it should give exactly one nonce
    // which is expired.
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
    let nonce2;
    // create a new nonce token for the same account
    try {
      nonce2 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
    } catch(e) {
      err = e;
    }
    assertNoError(err);
    should.exist(nonce2);
    let result2;
    // get all existing nonce tokens for the account again.
    // since one of the tokens is expired, it gets deleted when nonce2 is set
    // and so, in result2 we should get only one nonce(which is nonce2).
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
    result2.length.should.equal(1);
  });
});
