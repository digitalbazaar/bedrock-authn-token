/*
 * Copyright (c) 2018-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brAccount = require('bedrock-account');
const brAuthnToken = require('bedrock-authn-token');
const {prepareDatabase} = require('./helpers.js');
const mockData = require('./mock.data');

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
        result.should.have.keys(['type', 'challenge']);
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
      result.should.have.keys(['type', 'challenge']);
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
      result.should.have.keys(['type', 'challenge']);
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
    it('should generate a new nonce if one already exists', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const actor = await brAccount.getCapabilities({id: accountId});
      let err;
      let result1;
      // create a new nonce token
      const nonce1 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });
      try {
        result1 = await brAuthnToken.get({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result1);
      should.exist(nonce1);

      // create another nonce token
      const nonce2 = await brAuthnToken.set({
        account: accountId,
        actor,
        type: 'nonce',
      });

      let result2;
      try {
        result2 = await brAuthnToken.get({
          account: accountId,
          actor,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      assertNoError(err);
      should.exist(result1);
      should.exist(nonce2);
      result1.should.not.eql(result2);
      nonce1.challenge.should.not.equal(nonce2.challenge);
    });
  });
});
