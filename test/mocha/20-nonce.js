/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';
import * as brAuthnToken from '@bedrock/authn-token';
import {prepareDatabase} from './helpers.js';
import {mockData} from './mock.data.js';
import sinon from 'sinon';

describe('Nonce API', () => {
  describe('set', () => {
    // NOTE: the accounts collection is getting erased before each test
    // this allows for the creation of tokens using the same account info
    beforeEach(async () => {
      await prepareDatabase(mockData);
    });
    it('should set a challenge', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          accountId,
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
    it('should set a challenge of length 6 if "typeOptions" is not given',
      async () => {
        const accountId = mockData.accounts['alpha@example.com'].account.id;
        let result;
        let err;
        try {
          result = await brAuthnToken.set({
            accountId,
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
        result.challenge.should.match(/^\d{6}$/);
      });
    it('should set a challenge of length 6 if "typeOptions.entryStyle" is ' +
      'set to "human"',
    async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          accountId,
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
      result.challenge.should.match(/^\d{6}$/);
    });
    it('should set a challenge of length 23 if "typeOptions.entryStyle" ' +
      'is set to "machine"', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          accountId,
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
      let result;
      let err;
      try {
        result = await brAuthnToken.set({
          accountId,
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
      let err;
      // create three new nonce tokens
      const nonce1 = await brAuthnToken.set({
        accountId,
        type: 'nonce',
      });
      const nonce2 = await brAuthnToken.set({
        accountId,
        type: 'nonce',
      });
      const nonce3 = await brAuthnToken.set({
        accountId,
        type: 'nonce',
      });
      let result;
      try {
        result = await brAuthnToken.getAll({
          accountId,
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
          type: 'nonce',
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
    it('should throw error if too many nonces are created', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      const {maxNonceCount} = bedrock.config['authn-token'].nonce;

      // create max nonce tokens
      for(let i = 0; i < maxNonceCount; ++i) {
        const nonce = await brAuthnToken.set({accountId, type: 'nonce'});
        should.exist(nonce);
      }
      // try to create another nonce token when others haven't expired;
      // it should throw an error
      let nonce;
      let err;
      try {
        nonce = await brAuthnToken.set({
          accountId,
          type: 'nonce',
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(nonce);
      should.exist(err);
      err.name.should.equal('NotAllowedError');
      err.message.should.equal(
        `No more than ${maxNonceCount} tokens can be pending at once.`);
    });
    it('should get a nonce with an "id"', async () => {
      const accountId = mockData.accounts['alpha@example.com'].account.id;
      // create two nonces
      const nonce1 = await brAuthnToken.set({
        accountId,
        type: 'nonce',
      });
      should.exist(nonce1);
      nonce1.should.have.keys(['challenge', 'id', 'type']);
      nonce1.type.should.equal('nonce');
      const nonce2 = await brAuthnToken.set({
        accountId,
        type: 'nonce',
      });
      should.exist(nonce2);
      nonce2.should.have.keys(['challenge', 'id', 'type']);
      nonce2.type.should.equal('nonce');
      // get nonce1 using its id, the result of get should have the same id as
      // nonce1
      const result = await brAuthnToken.get({
        accountId,
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
      // set a nonce for the account
      const nonce = await brAuthnToken.set({
        accountId,
        type: 'nonce',
      });
      should.exist(nonce);
      nonce.should.have.keys(['type', 'id', 'challenge']);
      // getAll nonce for the account
      let result;
      let err;
      try {
        result = await brAuthnToken.getAll({
          accountId,
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
        'authenticationMethod', 'requiredAuthenticationMethods', 'id',
        'hashParameters', 'sha256', 'expires'
      ]);
      // get challenge from nonce and hash it using the same salt
      const challenge = nonce.challenge;
      const {hash} = await brAuthnToken._pbkdf2.pbkdf2({
        secret: challenge,
        iterations: result.tokens[0].hashParameters.params.i,
        salt: result.tokens[0].hashParameters.salt
      });
      // verify the nonce token
      let verifyResult;
      let err2;
      try {
        verifyResult = await brAuthnToken.verify({
          accountId,
          type: 'nonce',
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
      // set a nonce for the account
      const nonce = await brAuthnToken.set({
        accountId,
        type: 'nonce',
      });
      should.exist(nonce);
      nonce.should.have.keys(['type', 'id', 'challenge']);

      const challenge = nonce.challenge;
      // make a different hash
      const {hash} = await brAuthnToken._pbkdf2.pbkdf2({
        secret: challenge + 'different'
      });
      // verify the nonce token
      let verifyResult;
      let err;
      try {
        verifyResult = await brAuthnToken.verify({
          accountId,
          type: 'nonce',
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
      // set a nonce with an older date.
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      const clock = sinon.useFakeTimers(yesterday.getTime());

      let err;
      let nonce;
      try {
        nonce = await brAuthnToken.set({
          accountId,
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
          accountId,
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
        'authenticationMethod', 'requiredAuthenticationMethods', 'id',
        'hashParameters', 'sha256', 'expires'
      ]);

      // undo the stub
      clock.restore();

      // get challenge from nonce and hash it using the same salt
      const challenge = nonce.challenge;
      const {hash} = await brAuthnToken._pbkdf2.pbkdf2({
        secret: challenge, phc: result.tokens[0].hashParameters
      });

      // verify the nonce token
      let verifyResult;
      let err3;
      try {
        verifyResult = await brAuthnToken.verify({
          accountId,
          type: 'nonce',
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
    // set a token with an older date.
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const clock = sinon.useFakeTimers(yesterday.getTime());
    let nonce1;
    let err;
    try {
      nonce1 = await brAuthnToken.set({
        accountId,
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
        accountId,
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
      'authenticationMethod', 'requiredAuthenticationMethods', 'id',
      'hashParameters', 'sha256', 'expires'
    ]);
    // undo the stub
    clock.restore();
    // get all existing nonce for the same account again after undoing the stub,
    // it should give an empty array as getAll drops any expired token.
    let result2;
    try {
      result2 = await brAuthnToken.getAll({
        accountId,
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

describe('Nonce storage', () => {
  let accountId;
  let nonce;
  // NOTE: the accounts collection is getting erased before each test
  // this allows for the creation of tokens using the same account info
  beforeEach(async () => {
    await prepareDatabase(mockData);
    accountId = mockData.accounts['alpha@example.com'].account.id;
    const accountId2 = mockData.accounts['beta@example.com'].account.id;

    // creates token
    nonce = await brAuthnToken.set({
      accountId,
      type: 'nonce'
    });
    // second token is created here in order to do proper assertions for
    // 'nReturned', 'totalKeysExamined' and 'totalDocsExamined'.
    await brAuthnToken.set({
      accountId: accountId2,
      type: 'nonce'
    });
  });
  it('pushToken() for set() using id', async () => {
    // FIXME: remove `explain`
    const accountId3 = mockData.accounts['gamma@example.com'].account.id;
    const {executionStats} = await brAuthnToken._tokenStorage.pushToken({
      accountId: accountId3,
      type: 'nonce',
      maxCount: 10,
      explain: true
    });
    executionStats.nReturned.should.equal(1);
    executionStats.totalKeysExamined.should.equal(1);
    executionStats.totalDocsExamined.should.equal(1);
    executionStats.executionStages.inputStage.inputStage.stage
      .should.equal('IXSCAN');
  });
  it('pushToken() for set() using email', async () => {
    // FIXME: remove `explain`
    const accountId3 = mockData.accounts['gamma@example.com'].account.id;
    const record = await brAccount.get({id: accountId3});
    const email = record.account.email;
    const {executionStats} = await brAuthnToken._tokenStorage.pushToken({
      email,
      type: 'nonce',
      maxCount: 10,
      explain: true
    });
    executionStats.nReturned.should.equal(1);
    executionStats.totalKeysExamined.should.equal(1);
    executionStats.totalDocsExamined.should.equal(1);
    executionStats.executionStages.inputStage.inputStage.stage
      .should.equal('IXSCAN');
  });
  it('removeToken() for remove()', async () => {
    const result = await brAuthnToken._tokenStorage.removeToken({
      accountId,
      type: 'nonce',
      id: nonce.id,
      explain: true
    });
    should.exist(result);
    result.should.equal(true);
  });
});
