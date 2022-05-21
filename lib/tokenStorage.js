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
    const tokenIdKey = `meta.bedrock-authn-token.tokens.${type}.id`;
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

  // if no matching record or a token was required and an empty array was found
  // then throw `NotFoundError`
  const result = record?.meta?.['bedrock-authn-token']?.tokens?.[type];
  if(!record ||
    (requireToken && Array.isArray(result) && result.length === 0)) {
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

export async function pushToken({
  accountId, email, type, token, maxCount, explain
} = {}) {
  const maxIndex = maxCount - 1;
  const query = {
    // push token the max index does not exist
    [`meta.bedrock-authn-token.tokens.${type}.${maxIndex}`]: {$exists: false}
  };
  return _addToken(
    {accountId, email, query, type, token, op: '$push', explain});
}

export async function setToken({accountId, email, type, token, explain} = {}) {
  const updated = await _addToken(
    {accountId, email, type, token, op: '$set', explain});
  if(explain) {
    // return explain result
    return updated;
  }
  if(!updated) {
    throw new BedrockError(
      'Could not set authentication token. Account not found.',
      'NotFoundError', {httpStatusCode: 404, public: true});
  }
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

export async function removeExpiredTokens({
  accountId, email, type, explain
} = {}) {
  const query = {
    $or: [{
      [`meta.bedrock-authn-token.tokens.${type}.expires`]: {$lte: new Date()}
    }, {
      // also remove any legacy bcrypt tokens
      [`meta.bedrock-authn-token.tokens.${type}.salt`]: {$exists: true}
    }]
  };
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

  const update = {
    $pull: {
      [`meta.bedrock-authn-token.tokens.${type}`]: {
        $or: [{
          expires: {$lte: new Date()}
        }, {
          // also remove any legacy bcrypt tokens
          salt: {$exists: true}
        }]
      }
    }
  };
  const result = await database.collections.account.updateOne(query, update);
  return result.result.n > 0;
}

async function _addToken({
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

  // add token to account `meta`
  const update = {
    [op]: {
      [`meta.bedrock-authn-token.tokens.${type}`]: token
    }
  };
  const result = await database.collections.account.updateOne(query, update);
  return result.result.n > 0;
}

/**
 * An object containing information on the query plan.
 *
 * @typedef {object} ExplainObject
 */
