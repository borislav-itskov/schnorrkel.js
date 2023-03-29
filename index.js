const { ethers } = require('ethers')
const secp256k1 = require('secp256k1')
const { randomBytes } = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const generatorPoint = ec.g;
const BigInteger = require('bigi')

const ecurve = require('ecurve');
const curve = ecurve.getCurveByName('secp256k1');
const n = curve.n

module.exports = class Schnorrkel {
  #nonces = {};

  #clearNonces(x) {
    this.#nonces[x] = {}
  }

  #setNonces(x) {
    const k = randomBytes(32);
    const kTwo = randomBytes(32);
    const kPublic = secp256k1.publicKeyCreate(k)
    const kTwoPublic = secp256k1.publicKeyCreate(kTwo)

    this.#nonces[x] = {
      k,
      kTwo,
      kPublic,
      kTwoPublic,
    }
  }

  #aCoefficient(publicKey, L) {
    return ethers.utils.arrayify(ethers.utils.solidityKeccak256(
      ["bytes", "bytes"],
      [L, publicKey]
    ));
  }

  #bCoefficient(combinedPublicKey, msgHash, publicNonces) {
    const arrayColumn = (arr, n) => arr.map(x => x[n]);
    const kPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 0));
    const kTwoPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 1));
    return ethers.utils.arrayify(ethers.utils.solidityKeccak256(
      ["bytes", "bytes32", "bytes", "bytes"],
      [combinedPublicKey, msgHash, kPublicNonces, kTwoPublicNonces]
    ));
  }

  #hashMessage(message) {
      return ethers.utils.solidityKeccak256(['string'], [message])
  }

  #challenge(R, m, publicKey) {
    // convert R to address
    var R_uncomp = secp256k1.publicKeyConvert(R, false);
    var R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32)

    // e = keccak256(address(R) || compressed publicKey || m)
    return ethers.utils.arrayify(
        ethers.utils.solidityKeccak256(
            ["address", "uint8", "bytes32", "bytes32"],
            [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), m]
        )
    )
  }

  #concatTypedArrays(publicKeys) {
    var c = new (publicKeys[0].constructor)(publicKeys.reduce((partialSum, publicKey) => partialSum + publicKey.length, 0))
    publicKeys.map((publicKey,index) => c.set(publicKey, (index * publicKey.length)))
    return c;
  }

  #areBuffersSame(buf1, buf2)
  {
      if (buf1.byteLength != buf2.byteLength) return false;

      var dv1 = new Int8Array(buf1);
      var dv2 = new Int8Array(buf2);
      for (var i = 0 ; i != buf1.byteLength ; i++)
      {
          if (dv1[i] != dv2[i]) return false;
      }

      return true;
  }

  generatePublicNonces(x) {
    this.#setNonces(x)
    return [this.#nonces[x].kPublic, this.#nonces[x].kTwoPublic]
  }

  getCombinedPublicKey(publicKeys) {
    const L = this.#concatTypedArrays(publicKeys);

    const modifiedKeys = publicKeys.map(publicKey => {
      return secp256k1.publicKeyTweakMul(publicKey, this.#aCoefficient(publicKey, L));
    })

    return secp256k1.publicKeyCombine(modifiedKeys);
  }

  getCombinedAddress(publicKeys) {
    const combinedPublicKey = this.getCombinedPublicKey(publicKeys)
    const px = ethers.utils.hexlify(combinedPublicKey.slice(1,33))
    return "0x" + px.slice(px.length - 40, px.length)
  }

  sign(msg, privateKey) {
      const hash = this.#hashMessage(msg)
      const publicKey = secp256k1.publicKeyCreate(privateKey)

      // R = G * k
      var k = randomBytes(32)
      var R = secp256k1.publicKeyCreate(k)

      // e = h(address(R) || compressed pubkey || m)
      var e = this.#challenge(R, hash, publicKey)

      // xe = x * e
      var xe = secp256k1.privateKeyTweakMul(privateKey, e)

      // s = k + xe
      var s = secp256k1.privateKeyTweakAdd(k, xe)

      return {R, s, e}
  }

  // publicNonces = [
  //   [k, ktwo], // for signer 1
  //   [k, ktwo], // for signer 2
  //   [k, ktwo], // for signer 3
  //   ...
  // ]
  multiSigSign(x, msg, publicKeys, publicNonces) {
    if (!(x in this.#nonces) || Object.keys(this.#nonces[x]).length === 0) {
      throw Error('Nonces should be exchanged before signing');
    }

    const publicKey = secp256k1.publicKeyCreate(x)
    const L = this.#concatTypedArrays(publicKeys);
    const combinedPublicKey = this.getCombinedPublicKey(publicKeys);
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const a = this.#aCoefficient(publicKey, L);
    const b = this.#bCoefficient(combinedPublicKey, msgHash, publicNonces);

    const effectiveNonces = publicNonces.map((batch) => {
      return secp256k1.publicKeyCombine([batch[0], secp256k1.publicKeyTweakMul(batch[1], b)])
    })
    const signerEffectiveNonce = secp256k1.publicKeyCombine([
      this.#nonces[x].kPublic,
      secp256k1.publicKeyTweakMul(this.#nonces[x].kTwoPublic, b)
    ])
    const inArray = effectiveNonces.filter(nonce => this.#areBuffersSame(nonce, signerEffectiveNonce)).length != 0;
    if (! inArray) {
      throw Error('Passed nonces are invalid');
    }

    const e = this.#challenge(secp256k1.publicKeyCombine(effectiveNonces), msgHash, combinedPublicKey)

    const k = this.#nonces[x].k;
    const kTwo = this.#nonces[x].kTwo;

    // xe = x * e
    const xe = secp256k1.privateKeyTweakMul(x, e);

    // xea = a * xe
    const xea = secp256k1.privateKeyTweakMul(xe, a);

    // k + xea
    const kPlusxea = secp256k1.privateKeyTweakAdd(xea, k);

    // kTwo * b
    const kTwoMulB = secp256k1.privateKeyTweakMul(kTwo, b);

    // k + kTwoMulB + xea
    const final = secp256k1.privateKeyTweakAdd(kPlusxea, kTwoMulB);

    // absolutely crucial to delete the nonces once a signature has been crafted with them.
    // nonce reusae will lead to private key leakage!
    this.#clearNonces(x);

    return {
      // s = k + xea mod(n)
      s: BigInteger.fromBuffer(final).mod(n).toBuffer(32),
      e
    }
  }

  sumSigs(sigs) {
    var combined = BigInteger.fromBuffer(sigs[0]);
    sigs.shift();
    sigs.map(sig => {
      combined = combined.add(BigInteger.fromBuffer(sig));
    })
    return combined.mod(n).toBuffer(32);
  }

  verify(s, msg, R, publicKey) {
      const hash = this.#hashMessage(msg)
      const eC = this.#challenge(R, hash, publicKey)
      const sG = generatorPoint.mul(ethers.utils.arrayify(s))
      const P = ec.keyFromPublic(publicKey).getPublic()
      const Pe = P.mul(eC)
      R = ec.keyFromPublic(R).getPublic()
      const RplusPe = R.add(Pe)
      return sG.eq(RplusPe)
  }
}
