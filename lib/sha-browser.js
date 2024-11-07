/*
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
/* eslint-env browser */
const crypto = self && (self.crypto || self.msCrypto);

/**
 * Hashes a string of data using SHA-256 or SHA-384.
 *
 * @param {object} options - The options to use.
 * @param {string} options.algorithm - The algorithm to use.
 * @param {string} options.string - The string to hash.
 *
 * @returns {Uint8Array} The hash digest.
 */
export async function sha({algorithm, string}) {
  const bytes = new TextEncoder().encode(string);
  return new Uint8Array(await crypto.subtle.digest(algorithm, bytes));
}
