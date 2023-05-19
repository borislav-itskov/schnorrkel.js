import { ethers } from 'ethers';
import ecurve from 'ecurve';
import secp256k1 from 'secp256k1'
import elliptic from 'elliptic';

const EC = elliptic.ec;
const ec = new EC('secp256k1');
const generatorPoint = ec.g;

let bigi: any = null;
function getBigi(): any {
  if (!bigi) {
    bigi = require("bigi");
  }
  return bigi;
}

const curve = ecurve.getCurveByName('secp256k1');
const n = curve?.n

interface NoncePairs {
  readonly k: Uint8Array,
  readonly kTwo: Uint8Array,
  readonly kPublic: Uint8Array,
  readonly kTwoPublic: Uint8Array,
}

export interface PublicNonces {
  readonly kPublic: Uint8Array,
  readonly kTwoPublic: Uint8Array,
}

interface Nonces {
  [key: string]: NoncePairs
}

interface Signature {
  R: Uint8Array, // the final public nonce
  e: Uint8Array, // the schnorr challenge
  s: Uint8Array, // the signature
}

export class Schnorrkel {
  #nonces: Nonces = {};

  #clearNonces(x: Uint8Array): void {
    delete this.#nonces[ethers.utils.keccak256(x)]
  }

  #setNonces(x: Uint8Array): void {
    const k = ethers.utils.randomBytes(32);
    const kTwo = ethers.utils.randomBytes(32);
    const kPublic = secp256k1.publicKeyCreate(k)
    const kTwoPublic = secp256k1.publicKeyCreate(kTwo)

    this.#nonces[ethers.utils.keccak256(x)] = {
      k,
      kTwo,
      kPublic,
      kTwoPublic,
    }
  }

  #generateL(publicKeys: Uint8Array[]): string {
    return ethers.utils.keccak256(this.#concatTypedArrays(publicKeys.sort()));
  }

  #aCoefficient(publicKey: Uint8Array, L: string): Uint8Array {
    return ethers.utils.arrayify(ethers.utils.solidityKeccak256(
      ['bytes', 'bytes'],
      [L, publicKey]
    ));
  }

  #bCoefficient(combinedPublicKey: Uint8Array, msgHash: string, publicNonces: PublicNonces[]): Uint8Array {
    const arrayColumn = (arr: Array<PublicNonces>, n: string) => arr.map(x => x[n]);
    const kPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kPublic'));
    const kTwoPublicNonces = secp256k1.publicKeyCombine(arrayColumn(publicNonces, 'kTwoPublic'));

    return ethers.utils.arrayify(ethers.utils.solidityKeccak256(
      ['bytes', 'bytes32', 'bytes', 'bytes'],
      [combinedPublicKey, msgHash, kPublicNonces, kTwoPublicNonces]
    ));
  }

  // TODO: allow the user to choose the hashing function
  #hashMessage(message: string): string {
    return ethers.utils.solidityKeccak256(['string'], [message])
  }

  #challenge(R: Uint8Array, msgHash: string, publicKey: Uint8Array): Uint8Array {
    // convert R to address
    var R_uncomp = secp256k1.publicKeyConvert(R, false);
    var R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32)

    // e = keccak256(address(R) || compressed publicKey || msgHash)
    return ethers.utils.arrayify(
      ethers.utils.solidityKeccak256(
        ['address', 'uint8', 'bytes32', 'bytes32'],
        [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), msgHash]
      )
    )
  }

  #concatTypedArrays(publicKeys: Uint8Array[]) {
    var c = new ((publicKeys[0] as any).constructor)(publicKeys.reduce((partialSum, publicKey) => partialSum + publicKey.length, 0))
    publicKeys.map((publicKey,index) => c.set(publicKey, (index * publicKey.length)))
    return c;
  }

  #areBuffersSame(buf1: Uint8Array, buf2: Uint8Array): boolean {
    if (buf1.byteLength != buf2.byteLength) return false;

    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }

    return true;
  }

  generatePublicNonces(x: Uint8Array): PublicNonces {
    this.#setNonces(x)
    const xHashed = ethers.utils.keccak256(x)

    return {
      kPublic: this.#nonces[xHashed].kPublic,
      kTwoPublic: this.#nonces[xHashed].kTwoPublic
    }
  }

  getCombinedPublicKey(publicKeys: Uint8Array[]): Uint8Array {
    if (publicKeys.length < 2) throw Error('At least 2 public keys should be provided')

    const L = this.#generateL(publicKeys)
    const modifiedKeys = publicKeys.map(publicKey => {
      return secp256k1.publicKeyTweakMul(publicKey, this.#aCoefficient(publicKey, L));
    })

    return secp256k1.publicKeyCombine(modifiedKeys);
  }

  getCombinedAddress(publicKeys: Uint8Array[]): string {
    if (publicKeys.length < 2) throw Error('At least 2 public keys should be provided')

    const combinedPublicKey = this.getCombinedPublicKey(publicKeys)
    const px = ethers.utils.hexlify(combinedPublicKey.slice(1,33))
    return '0x' + px.slice(px.length - 40, px.length)
  }

  sign(x: Uint8Array, msg: string): Signature {
    const hash = this.#hashMessage(msg)
    const publicKey = secp256k1.publicKeyCreate((x as any))

    // R = G * k
    var k = ethers.utils.randomBytes(32)
    var R = secp256k1.publicKeyCreate(k)

    // e = h(address(R) || compressed pubkey || m)
    var e = this.#challenge(R, hash, publicKey)

    // xe = x * e
    var xe = secp256k1.privateKeyTweakMul((x as any), e)

    // s = k + xe
    var s = secp256k1.privateKeyTweakAdd(k, xe)

    return {R, s, e}
  }

  multiSigSign(x: Uint8Array, msg: string, publicKeys: Uint8Array[], publicNonces: PublicNonces[]): Signature {
    if (publicKeys.length < 2) throw Error('At least 2 public keys should be provided')

    const xHashed = ethers.utils.keccak256(x)
    if (!(xHashed in this.#nonces) || Object.keys(this.#nonces[xHashed]).length === 0) {
      throw Error('Nonces should be exchanged before signing');
    }

    const publicKey = secp256k1.publicKeyCreate(x)
    const L = this.#generateL(publicKeys)
    const combinedPublicKey = this.getCombinedPublicKey(publicKeys);
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const a = this.#aCoefficient(publicKey, L);
    const b = this.#bCoefficient(combinedPublicKey, msgHash, publicNonces);

    const effectiveNonces = publicNonces.map((batch) => {
      return secp256k1.publicKeyCombine([batch.kPublic, secp256k1.publicKeyTweakMul(batch.kTwoPublic, b)])
    })
    const signerEffectiveNonce = secp256k1.publicKeyCombine([
      this.#nonces[xHashed].kPublic,
      secp256k1.publicKeyTweakMul(this.#nonces[xHashed].kTwoPublic, b)
    ])
    const inArray = effectiveNonces.filter(nonce => this.#areBuffersSame(nonce, signerEffectiveNonce)).length != 0;
    if (! inArray) {
      throw Error('Passed nonces are invalid');
    }

    const R = secp256k1.publicKeyCombine(effectiveNonces);
    const e = this.#challenge(R, msgHash, combinedPublicKey)

    const k = this.#nonces[xHashed].k;
    const kTwo = this.#nonces[xHashed].kTwo;

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
      s: getBigi().fromBuffer(final).mod(n).toBuffer(32),
      e,
      R
    }
  }

  sumSigs(sigs: Uint8Array[]): Uint8Array {
    var combined = getBigi().fromBuffer(sigs[0]);
    sigs.shift();
    sigs.map(sig => {
      combined = combined.add(getBigi().fromBuffer(sig));
    })
    return combined.mod(n).toBuffer(32);
  }

  verify(s: Uint8Array, msg: string, R: Uint8Array, publicKey: Uint8Array): boolean {
    const hash = this.#hashMessage(msg)
    const eC = this.#challenge(R, hash, publicKey)
    const sG = generatorPoint.mul(ethers.utils.arrayify(s))
    const P = ec.keyFromPublic(publicKey).getPublic()
    const Pe = P.mul(eC)
    const toPublicR = ec.keyFromPublic(R).getPublic()
    const RplusPe = toPublicR.add(Pe)
    return sG.eq(RplusPe)
  }
}
