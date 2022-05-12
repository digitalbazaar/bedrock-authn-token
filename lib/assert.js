/*!
 * Copyright (c) 2022 Digital Bazaar, Inc. All rights reserved.
 */
import {default as assertPlus} from 'assert-plus';

export const assert = {
  nonNegativeSafeInteger, uint8Array, ...assertPlus
};

function nonNegativeSafeInteger(x, name) {
  if(!(x >= 0 && Number.isSafeInteger(x))) {
    throw new TypeError(`"${name}" must be a non-negative safe integer.`);
  }
}

function uint8Array(x, name) {
  if(!(x instanceof Uint8Array)) {
    throw new TypeError(`"${name}" must be a Uint8Array.`);
  }
}
