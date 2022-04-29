/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {v4 as uuid} from 'uuid';

export const mockData = {};
const accounts = mockData.accounts = {};

const emails = ['alpha@example.com', 'beta@example.com', 'gamma@example.com'];
for(const email of emails) {
  accounts[email] = {};
  accounts[email].account = _createAccount(email);
  accounts[email].meta = {};
}

function _createAccount(email) {
  const newAccount = {
    id: 'urn:uuid:' + uuid(),
    email
  };
  return newAccount;
}
