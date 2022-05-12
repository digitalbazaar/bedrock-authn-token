/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as database from '@bedrock/mongodb';

const {util: {BedrockError}} = bedrock;

export async function getAccountRecord({
  accountId, email, id, type, requireToken, explain
} = {}) {
  // tokens are found in account meta; query accordingly
  const typeKey = `meta.bedrock-authn-token.tokens.${type}`;
  const query = {};
  if(requireToken) {
    query[typeKey] = {$exists: true};
  }
  const projection = {
    _id: 0, 'account.id': 1, 'account.email': 1, [typeKey]: 1
  };
  if(accountId) {
    query.id = database.hash(accountId);
  } else {
    query['account.email'] = email;
  }

  if(id) {
    const tokenIdKey = 'meta.bedrock-authn-token.tokens.nonce.id';
    query[tokenIdKey] = id;
  }

  if(explain) {
    // 'find().limit(1)' is used here because 'findOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(
      query, {projection}).limit(1);
    return cursor.explain('executionStats');
  }

  const record = await database.collections.account.findOne(
    query, {projection});
  if(!record) {
    const subject = requireToken ? 'Authentication token' : 'Account';
    throw new BedrockError(`${subject} not found.`, {
      name: 'NotFoundError',
      details: {
        httpStatusCode: 404,
        public: true
      }
    });
  }
  return record;
}

export async function addToken({
  accountId, email, query, type, token, op, explain
}) {
  // update existing query
  query = {...query};
  if(accountId) {
    query.id = database.hash(accountId);
  } else {
    query['account.email'] = email;
  }

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  // set token in account `meta`
  const result = await database.collections.account.updateOne(
    query, {
      [op]: {
        [`meta.bedrock-authn-token.tokens.${type}`]: token
      }
    });
  return result.result.n > 0;
}

export async function removeToken({accountId, type, id, explain = false} = {}) {
  const query = {id: database.hash(accountId)};
  let update;
  const tokenTypeKey = `meta.bedrock-authn-token.tokens.${type}`;
  if(id && type === 'nonce') {
    update = {
      $pull: {
        [tokenTypeKey]: {id}
      }
    };
  } else {
    if(id) {
      query[`${tokenTypeKey.id}`] = id;
    }
    update = {
      $unset: {
        [tokenTypeKey]: true
      }
    };
  }

  if(explain) {
    // 'find().limit(1)' is used here because 'updateOne()' doesn't return a
    // cursor which allows the use of the explain function.
    const cursor = await database.collections.account.find(query).limit(1);
    return cursor.explain('executionStats');
  }

  // remove token from meta
  const result = await database.collections.account.updateOne(query, update);
  if(result.result.n === 0) {
    throw new BedrockError(
      'Could not remove authentication token. Account or token not found.',
      'NotFoundError', {httpStatusCode: 404, public: true});
  }
}

/**
 * An object containing information on the query plan.
 *
 * @typedef {object} ExplainObject
 */
