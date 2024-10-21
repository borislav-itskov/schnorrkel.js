import { arrayify, defaultAbiCoder } from "ethers/lib/utils";
import { _generateSchnorrAddr } from "../core";
import Schnorrkel from "../schnorrkel";
import { Key, PublicNonces, SignatureOutput } from "../types";

class SchnorrProvider {
  public readonly publicKey: Key;
  protected readonly _schnorrkel: Schnorrkel;

  constructor(publicKey: Key) {
    this.publicKey = publicKey;
    this._schnorrkel = new Schnorrkel();
  }

  getSchnorrAddress(): string {
    return _generateSchnorrAddr(this.publicKey.buffer);
  }

  getPublicNonces(): PublicNonces {
    return this._schnorrkel.generateOrGetPublicNonces();
  }

  /**
   * The onchain structure
   *
   * @param sigOutput
   * @returns hex forOnchainValidation
   */
  getEcrecoverSignature(sigOutput: SignatureOutput): string {
    const buffer = arrayify(this.publicKey.buffer);
    const px = buffer.slice(1, 33);
    const parity = buffer[0] - 2 + 27;
    return defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint8"],
      [px, sigOutput.challenge.buffer, sigOutput.signature.buffer, parity]
    );
  }
}

export default SchnorrProvider;
