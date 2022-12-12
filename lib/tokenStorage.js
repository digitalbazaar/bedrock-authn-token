/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as bedrock from '@bedrock/core';
import * as brAccount from '@bedrock/account';

const {util: {BedrockError}} = bedrock;

const META_KEY = 'bedrock-authn-token';

export async function getAccountRecord({
  accountId, email, id, type, requireToken
} = {}) {
  // get account record
  const options = {};
  if(accountId) {
    options.id = accountId;
  } else {
    options.email = email;
  }
  let record = await brAccount.get(options);

  // if a token is required or an `id` for the token was given, ensure the
  // record has such a token; get tokens of `type` to apply further filtering
  const tokens = record.meta?.[META_KEY]?.tokens?.[type];

  // `tokens` may be a single token or an array of tokens
  if(Array.isArray(tokens)) {
    if(id) {
      // specific token with `id` required, else record not found
      if(!tokens.some(t => t.id === id)) {
        record = null;
      }
    } else if(requireToken && tokens.length === 0) {
      // any token of `type` required, but none found; no matching record
      record = null;
    }
  } else {
    if(id) {
      // specific token with `id` required, else record not found
      if(tokens?.id !== id) {
        record = null;
      }
    } else if(requireToken && !tokens) {
      // any token of `type` required, but none found; no matching record
      record = null;
    }
  }

  // if no record found, throw `NotFoundError`
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

export async function pushToken({
  accountId, email, type, token, maxCount
} = {}) {
  return _addToken({accountId, email, type, token, op: 'push', maxCount});
}

export async function setToken({accountId, email, type, token} = {}) {
  return _addToken({accountId, email, type, token, op: 'set'});
}

export async function removeToken({accountId, type, id} = {}) {
  // ignore concurrent account updates when removing token(s)
  while(true) {
    try {
      // get existing record meta
      const record = await brAccount.get({id: accountId});
      // check for existing token(s)
      const tokens = record.meta?.[META_KEY]?.tokens?.[type];
      let hasToken = false;
      if(tokens) {
        if(id === undefined) {
          // no `id` given, at least one token must exist
          hasToken = !Array.isArray(tokens) || tokens.length > 0;
        } else if(Array.isArray(tokens)) {
          // one of the tokens must match the `id`
          hasToken = tokens.some(t => t.id === id);
        } else {
          // the token must match the `id`
          hasToken = tokens?.id === id;
        }
      }

      if(!hasToken) {
        throw new BedrockError(
          'Token not found.', {
            name: 'NotFoundError',
            details: {httpStatusCode: 404, public: true}
          });
      }

      // prepare to update meta
      const meta = {...record.meta, sequence: record.meta.sequence + 1};

      if(id) {
        if(Array.isArray(tokens)) {
          // remove the token from the array
          const filtered = tokens.filter(t => t.id !== id);
          if(filtered.length === 0) {
            // delete entire array
            delete meta[META_KEY].tokens[type];
          } else {
            meta[META_KEY].tokens[type] = filtered;
          }
        } else {
          // delete the token
          delete meta[META_KEY].tokens[type];
        }
      } else {
        // delete all tokens, no `id` specified
        delete meta[META_KEY].tokens[type];
      }

      return await brAccount.update({id: record.account.id, meta});
    } catch(e) {
      if(e.name === 'InvalidStateError') {
        // loop to try again; concurrently updated
        continue;
      }
      // differentiate not found error from other errors
      const notFound = e.name === 'NotFoundError';
      throw new BedrockError(
        'Could not remove authentication token. ' +
        notFound ? ' Account or token not found.' : '', {
          name: notFound ? 'NotFoundError' : 'OperationError',
          details: {httpStatusCode: notFound ? 404 : 500, public: true},
          cause: e
        });
    }
  }
}

export async function removeExpiredTokens({accountId, email, type} = {}) {
  // ignore concurrent account updates when removing expired tokens
  while(true) {
    try {
      // get existing record meta
      const record = await brAccount.get({id: accountId, email});
      // check for existing token(s)
      const tokens = record.meta?.[META_KEY]?.tokens?.[type];
      if(!tokens) {
        // nothing to remove, return
        return false;
      }

      // determine if there are any expired tokens
      let updatedTokens;
      const now = new Date();
      if(!Array.isArray(tokens)) {
        // also remove any legacy bcrypt tokens (indicated by `salt` presence)
        // note: if `tokens.expires` does not exist, then the comparison will
        // fail as desired
        if(!(tokens.salt || now > tokens.expires)) {
          // nothing to remove, return
          return false;
        }
      } else {
        // note: if `t.expires` does not exist, then the comparison will
        // fail as desired
        updatedTokens = tokens.filter(t => !(t.salt || now > t.expires));
        if(updatedTokens.length === tokens.length) {
          // nothing to remove, return
          return false;
        }
        if(updatedTokens.length === 0) {
          // no tokens remaining, clear entire array
          updatedTokens = undefined;
        }
      }

      // prepare to update meta
      const meta = {...record.meta, sequence: record.meta.sequence + 1};
      if(updatedTokens === undefined) {
        delete meta[META_KEY].tokens[type];
      } else {
        meta[META_KEY].tokens[type] = updatedTokens;
      }

      return await brAccount.update({id: record.account.id, meta});
    } catch(e) {
      if(e.name === 'InvalidStateError') {
        // loop to try again; concurrently updated
        continue;
      }
      // no tokens to remove if account has been removed
      if(e.name === 'NotFoundError') {
        return false;
      }
      // some other error
      throw new BedrockError(
        'Could not remove expired tokens.', {
          name: 'OperationError',
          details: {httpStatusCode: 500, public: true},
          cause: e
        });
    }
  }
}

async function _addToken({
  accountId, email, type, token, op, maxCount
}) {
  // ignore concurrent account updates when adding a token
  while(true) {
    try {
      // get existing record meta
      const record = await brAccount.get({id: accountId, email});

      // get any existing token(s)
      const tokens = record.meta?.[META_KEY]?.tokens?.[type];

      // prepare to update meta
      const meta = {...record.meta, sequence: record.meta.sequence + 1};
      if(op === 'push') {
        if(tokens && !Array.isArray(tokens)) {
          // should never happen unless code is called improperly with a
          // 'push' `op` on a single-token type
          throw new TypeError('Token type mismatch.');
        }
        if(!tokens) {
          // first token
          if(!meta[META_KEY]) {
            meta[META_KEY] = {tokens: {[type]: [token]}};
          } else if(!meta[META_KEY].tokens) {
            meta[META_KEY].tokens = {[type]: [token]};
          } else {
            meta[META_KEY].tokens[type] = [token];
          }
        } else if(tokens.length < maxCount) {
          // append token
          meta[META_KEY].tokens[type] = [...tokens, token];
        } else {
          // max token count reached
          return false;
        }
      } else {
        // presume `op` === 'set'
        if(tokens && Array.isArray(tokens)) {
          // should never happen unless code is called improperly with a
          // 'set' `op` on a multi-token type
          throw new TypeError('Token type mismatch.');
        }
        if(!meta[META_KEY]) {
          meta[META_KEY] = {tokens: {[type]: token}};
        } else if(!meta[META_KEY].tokens) {
          meta[META_KEY].tokens = {[type]: token};
        } else {
          meta[META_KEY].tokens[type] = token;
        }
      }
      return await brAccount.update({id: record.account.id, meta});
    } catch(e) {
      if(e.name === 'InvalidStateError') {
        // loop to try again; concurrently updated
        continue;
      }
      // differentiate not found error from other errors
      const notFound = e.name === 'NotFoundError';
      throw new BedrockError(
        'Could not add authentication token to account.' +
        notFound ? ' Account not found.' : '', {
          name: notFound ? 'NotFoundError' : 'OperationError',
          details: {httpStatusCode: notFound ? 404 : 500, public: true},
          cause: e
        });
    }
  }
}
