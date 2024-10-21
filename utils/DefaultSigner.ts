import Schnorrkel, { Key, PublicNonces } from '../src/index'
import { generateRandomKeys } from "../src/core";

export default class DefaultSigner {
  #schnorrkel = new Schnorrkel();
  #privateKey: Key;
  #publicKey: Key;

  constructor() {
    const keys = generateRandomKeys()
    this.#privateKey = keys.privateKey
    this.#publicKey = keys.publicKey
  }

  getPublicKey(): Key {
    return this.#publicKey;
  }

  getPublicNonces(): PublicNonces {
    return this.#schnorrkel.generatePublicNonces();
  }

  multiSignMessage(msg: string, publicKeys: Key[], publicNonces: PublicNonces[]) {
    return this.#schnorrkel.multiSigSign(this.#privateKey, msg, publicKeys, publicNonces);
  }
}