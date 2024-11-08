/*
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from 'node:crypto';

const REQUIRED_HASH_ALGORITHM = 'sha256';

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
  return new Uint8Array(crypto.createHash(algorithm).update(string).digest());
}
