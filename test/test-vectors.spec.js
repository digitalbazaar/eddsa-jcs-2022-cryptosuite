/*!
 * Copyright (c) 2024 Digital Bazaar, Inc. All rights reserved.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {createSignCryptosuite, createVerifyCryptosuite} from '../lib/index.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {expect} from 'chai';
import jsigs from 'jsonld-signatures';
import {loader} from './documentLoader.js';

import * as testVectors from './test-vectors.js';

const {purposes: {AssertionProofPurpose}} = jsigs;

const documentLoader = loader.build();

describe('test vectors', () => {
  let keyPair;
  before(async () => {
    const {keyMaterial} = testVectors;
    keyPair = await Ed25519Multikey.from(keyMaterial);
    keyPair.controller = `did:key:${keyPair.publicKeyMultibase}`;
    keyPair.id = `${keyPair.controller}#${keyPair.publicKeyMultibase}`;
  });

  it('should create proof', async () => {
    const {signFixture} = testVectors;
    const unsigned = {...signFixture};
    delete unsigned.proof;

    const signer = keyPair.signer();
    const date = new Date(signFixture.proof.created);

    let error;
    let signed;
    try {
      const cryptosuite = createSignCryptosuite();
      signed = await jsigs.sign(unsigned, {
        suite: new DataIntegrityProof({cryptosuite, signer, date}),
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    } catch(e) {
      error = e;
    }

    expect(error).to.not.exist;
    expect(signed).to.deep.equal(signFixture);
  });

  it('should verify signed fixture', async () => {
    const {verifyFixture} = testVectors;

    const cryptosuite = createVerifyCryptosuite();
    const result = await jsigs.verify(verifyFixture, {
      suite: new DataIntegrityProof({cryptosuite}),
      purpose: new AssertionProofPurpose(),
      documentLoader
    });
    expect(result.verified).to.be.true;
  });
});
