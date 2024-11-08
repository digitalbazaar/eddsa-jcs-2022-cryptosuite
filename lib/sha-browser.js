/*
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
/* eslint-env browser */
const crypto = self && (self.crypto || self.msCrypto);

const REQUIRED_HASH_ALGORITHM = 'SHA-256';

/**
 * Hashes a string of data using SHA-256.
 *
 * @param {object} options - The options to use.
 * @param {string} options.string - The string to hash.
 *
 * @returns {Uint8Array} The hash digest.
 */
export async function sha({string}) {
  const algorithm = REQUIRED_HASH_ALGORITHM;
  const bytes = new TextEncoder().encode(string);
  return new Uint8Array(await crypto.subtle.digest(algorithm, bytes));
}
