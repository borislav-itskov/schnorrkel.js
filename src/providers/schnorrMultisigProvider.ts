import { arrayify, defaultAbiCoder } from "ethers/lib/utils";
import { _generateSchnorrAddr } from "../core";
import Schnorrkel from "../schnorrkel";
import { PublicNonces, SignatureOutput } from "../types";
import SchnorrProvider from "./schnorrProvider";

class SchnorrMultisigProvider {
  private _schnorrProviders: SchnorrProvider[];

  constructor(schnorrProviders: SchnorrProvider[]) {
    this._schnorrProviders = schnorrProviders;
  }

  addProvider(schnorrProvider: SchnorrProvider) {
    this._schnorrProviders.push(schnorrProvider);
  }

  getPublicKeys() {
    return this._schnorrProviders.map((provider) => provider.publicKey);
  }

  getSchnorrAddress(): string {
    return _generateSchnorrAddr(
      Schnorrkel.getCombinedPublicKey(this.getPublicKeys()).buffer
    );
  }

  /**
   * Call this method only once to retrieve the nonces.
   * Do not call it again until all signatures have concluded
   * @returns
   */
  getPublicNonces(): PublicNonces[] {
    return this._schnorrProviders.map((provider) => provider.getPublicNonces());
  }

  getEcrecoverSignature(sigOutputs: SignatureOutput[]): string {
    const publicKey = arrayify(
      Schnorrkel.getCombinedPublicKey(this.getPublicKeys()).buffer
    );
    const sSummed = Schnorrkel.sumSigs(
      sigOutputs.map((output) => output.signature)
    );
    const challenge = sigOutputs[0].challenge;
    const px = publicKey.slice(1, 33);
    const parity = publicKey[0] - 2 + 27;
    return defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint8"],
      [px, challenge.buffer, sSummed.buffer, parity]
    );
  }
}

export default SchnorrMultisigProvider;
