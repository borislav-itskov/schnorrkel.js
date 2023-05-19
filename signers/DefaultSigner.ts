import { config, ethers } from "hardhat";
import secp256k1 from 'secp256k1'
import { PublicNonces, Schnorrkel } from "..";
const schnorrkel = new Schnorrkel();

export class DefaultSigner {

  #privateKey: Uint8Array;
  #publicKey: Uint8Array;

  constructor(index: number) {
    this.#privateKey = this.#generatePrivateKey(index)
    this.#publicKey = secp256k1.publicKeyCreate(this.#privateKey);
  }

  #generatePrivateKey(index: number): Uint8Array {
    const accounts: any = config.networks.hardhat.accounts
    const wallet = ethers.Wallet.fromMnemonic(accounts.mnemonic, accounts.path + `/${index}`)
    return ethers.utils.arrayify(wallet.privateKey);
  }

  getPublicKey(): Uint8Array {
    return this.#publicKey;
  }

  getPublicNonces(): PublicNonces {
    return schnorrkel.generatePublicNonces(this.#privateKey);
  }

  multiSignMessage(msg: string, publicKeys: Uint8Array[], publicNonces: PublicNonces[]) {
    return schnorrkel.multiSigSign(this.#privateKey, msg, publicKeys, publicNonces);
  }
}