/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {config} from '@bedrock/core';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import '@bedrock/mongodb';
import '@bedrock/authn-token';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

config.mocha.tests.push(path.join(__dirname, 'mocha'));

// set tester email
config['authn-token'].nonce.testerAccounts = [{
  id: 'urn:uuid:a1fa7222-a019-440a-8f27-302d448f1c4d',
  email: 'tester@example.com'
}];

// MongoDB
config.mongodb.name = 'bedrock_authn_token_test';
config.mongodb.dropCollections.onInit = true;
config.mongodb.dropCollections.collections = [];
