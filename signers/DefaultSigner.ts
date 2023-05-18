import { config, ethers } from "hardhat";
import { Schnorrkel } from "..";

const schnorrkel = new Schnorrkel();
const secp256k1 = require('secp256k1')

module.exports = class DefaultSigner {

  #privateKey;
  #publicKey;

  constructor(index) {
    this.#privateKey = this.#generatePrivateKey(index)
    this.#publicKey = secp256k1.publicKeyCreate(this.#privateKey);
  }

  #generatePrivateKey(index) {
    const accounts: any = config.networks.hardhat.accounts
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${index}`)
    return ethers.utils.arrayify(wallet.privateKey);
  }

  getPublicKey() {
    return this.#publicKey;
  }

  getPublicNonces() {
    return schnorrkel.generatePublicNonces(this.#privateKey);
  }

  multiSignMessage(msg, publicKeys, publicNonces) {
    return schnorrkel.multiSigSign(this.#privateKey, msg, publicKeys, publicNonces);
  }
}