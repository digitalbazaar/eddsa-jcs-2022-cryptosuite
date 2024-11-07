/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
*/
import {canonize} from './canonize.js';
import {createVerifier} from './createVerifier.js';
import {name} from './name.js';
import {requiredAlgorithm} from './requiredAlgorithm.js';
import {sha} from './sha.js';

export function createSignCryptosuite() {
  return {
    name,
    canonize,
    requiredAlgorithm,
    createVerifier: _throwSignUsageError,
    createVerifyData: _createVerifyDataFn(
      _modifySignProofOptionsAndDocument
    ),
  };
}

export function createVerifyCryptosuite() {
  return {
    name,
    canonize,
    requiredAlgorithm,
    createVerifier,
    createVerifyData: _createVerifyDataFn(
      _modifyVerifyProofOptionsAndDocument
    ),
  };
}

function _createVerifyDataFn(modifyProofOptionsAndDocument) {
  return async function({cryptosuite, document, proof} = {}) {
    if(cryptosuite?.name !== name) {
      throw new TypeError(`"cryptosuite.name" must be "${name}".`);
    }
    // determine digest algorithm from key algorithm
    modifyProofOptionsAndDocument({proof, document});

    // await both jcs proof hash and jcs document hash
    const [proofHash, docHash] = await Promise.all([
      // canonize and hash proof
      _canonizeProof(proof, {cryptosuite}).then(
        jcsProofOptions => sha({string: jcsProofOptions})),
      // canonize and hash document
      cryptosuite.canonize(document).then(
        jcsDocument => sha({string: jcsDocument}))
    ]);

    // concatenate hash of jcs proof options and hash of c14n document
    return _concat(proofHash, docHash);
  };
}

function _modifyVerifyProofOptionsAndDocument({proof, document}) {
  // 4) If proofOptions.@context exists:
  if(proof['@context']) {
    let proofContext = proof['@context'];
    proofContext = Array.isArray(proofContext) ? proofContext : [proofContext];
    let docContext = document['@context'];
    docContext = Array.isArray(docContext) ? docContext : [docContext];

    // 4.1) Check that the securedDocument.@context starts with all values
    // contained in the proofOptions.@context in the same order. Otherwise, set
    // verified to false and skip to the last step.
    for(let i = 0; i < proofContext.length; i++) {
      if(proofContext[i] !== docContext[i]) {
        throw new Error('document.@context does not start with proof.@context');
      }
    }
    // 4.2) Set unsecuredDocument.@context equal to proofOptions.@context.
    document['@context'] = proof['@context'];
  }
}

function _modifySignProofOptionsAndDocument({proof, document}) {
  // 2) If unsecuredDocument.@context is present, set proof.@context to
  //    unsecuredDocument.@context.
  if(document['@context']) {
    proof['@context'] = document['@context'];
  }
}

async function _canonizeProof(proofOptions, {cryptosuite}) {
  const proof = {...proofOptions};
  // `proofValue` must not be included in the proof options
  delete proof.proofValue;
  return cryptosuite.canonize(proof);
}

function _concat(b1, b2) {
  const rval = new Uint8Array(b1.length + b2.length);
  rval.set(b1, 0);
  rval.set(b2, b1.length);
  return rval;
}

function _throwSignUsageError() {
  throw new Error('This cryptosuite must only be used with "sign".');
}
