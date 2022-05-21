/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as brAuthnToken from '@bedrock/authn-token';

describe('pbkdf2 API', () => {
  it('should create a pbkdf2 hash', async () => {
    const {
      algorithm, salt, derivedBits, hash, phc
    } = await brAuthnToken._pbkdf2.pbkdf2({
      iterations: 1000,
      secret: 'password',
      saltSize: 16
    });
    should.exist(algorithm);
    algorithm.should.be.an('object');
    should.exist(salt);
    (salt instanceof Uint8Array).should.equal(true);
    should.exist(derivedBits);
    (derivedBits instanceof Uint8Array).should.equal(true);
    should.exist(hash);
    hash.should.be.a('string');
    hash.should.include('$pbkdf2-sha512$i=1000$');
    should.exist(phc);
    phc.should.be.an('object');
  });
  it('should create the same pbkdf2 hash with the same salt', async () => {
    const {
      algorithm, salt, derivedBits, hash, phc
    } = await brAuthnToken._pbkdf2.pbkdf2({
      iterations: 1000,
      secret: 'password',
      saltSize: 16
    });
    should.exist(algorithm);
    algorithm.should.be.an('object');
    should.exist(salt);
    (salt instanceof Uint8Array).should.equal(true);
    should.exist(derivedBits);
    (derivedBits instanceof Uint8Array).should.equal(true);
    should.exist(hash);
    hash.should.be.a('string');
    hash.should.include('$pbkdf2-sha512$i=1000$');
    should.exist(phc);
    phc.should.be.an('object');
    const {salt: saltB64} = phc;
    saltB64.should.be.a('string');

    const {hash: hash2} = await brAuthnToken._pbkdf2.pbkdf2({
      iterations: 1000,
      secret: 'password',
      // pass salt as uint8array
      salt
    });
    hash2.should.eql(hash);

    const {hash: hash3} = await brAuthnToken._pbkdf2.pbkdf2({
      iterations: 1000,
      secret: 'password',
      // pass salt as a string
      salt: saltB64
    });
    hash3.should.eql(hash);
  });
  it('should roundtrip a pch object', async () => {
    const {phc, hash} = await brAuthnToken._pbkdf2.pbkdf2({
      iterations: 1000,
      secret: 'password',
      saltSize: 16
    });
    should.exist(phc);
    should.exist(phc.id);
    phc.id.should.eql('pbkdf2-sha512');
    should.exist(phc.params);
    should.exist(phc.params.i);
    phc.params.i.should.eql(1000);
    const phc2 = brAuthnToken._pbkdf2.deserializePhc({hash});
    phc2.should.eql(phc);

    const hash2 = brAuthnToken._pbkdf2.serializePhc({phc});
    hash2.should.eql(hash);

    const phc3 = brAuthnToken._pbkdf2.deserializePhc({hash: hash2});
    phc2.should.eql(phc3);
  });
});
