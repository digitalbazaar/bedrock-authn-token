/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brAccount = require('bedrock-account');
const database = require('bedrock-mongodb');

exports.prepareDatabase = async mockData => {
  await exports.removeCollections();
  await _insertTestData(mockData);
};

exports.removeCollections = async (
  collectionNames = [
    'account',
  ]) => {
  await database.openCollections(collectionNames);
  for(const collectionName of collectionNames) {
    await database.collections[collectionName].deleteMany({});
  }
};

exports.removeCollection =
  async collectionName => exports.removeCollections([collectionName]);

async function _insertTestData(mockData) {
  const records = Object.values(mockData.accounts);
  for(const record of records) {
    try {
      await brAccount.insert(
        {account: record.account, meta: record.meta || {}});
    } catch(e) {
      if(e.name === 'DuplicateError') {
        // duplicate error means test data is already loaded
        continue;
      }
      throw e;
    }
  }
}
