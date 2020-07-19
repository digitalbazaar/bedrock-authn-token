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
        result.challenge.should.be.an('string');
        result.challenge.length.should.equal(9);
      });
    it('should set a challenge of length 9 if "typeOptions" is "human"',
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
            typeOptions: 'human'
          });
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.an('object');
        result.challenge.should.be.an('string');
        result.challenge.length.should.equal(9);
      });
    it('should set a challenge of length 23 if "typeOptions" is "machine"',
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
            typeOptions: 'machine'
          });
        } catch(e) {
          err = e;
        }
        assertNoError(err);
        should.exist(result);
        result.should.be.an('object');
        result.challenge.should.be.an('string');
        result.challenge.length.should.equal(23);
      });
  });
});
