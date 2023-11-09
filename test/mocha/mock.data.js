/*!
 * Copyright (c) 2018-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {v4 as uuid} from 'uuid';

export const mockData = {};
const accounts = mockData.accounts = {};

const emails = [
  'alpha@example.com', 'beta@example.com', 'gamma@example.com',
  'tester@example.com'
];
for(const email of emails) {
  accounts[email] = {};
  accounts[email].account = _createAccount(email);
  accounts[email].meta = {};
}

function _createAccount(email) {
  const newAccount = {
    // handle special `tester@example.com` case with static UUID
    id: email === 'tester@example.com' ?
      'urn:uuid:a1fa7222-a019-440a-8f27-302d448f1c4d' : 'urn:uuid:' + uuid(),
    email
  };
  return newAccount;
}
