import {
  arrayify,
  computePublicKey,
  defaultAbiCoder,
  isHexString,
} from "ethers/lib/utils";
import { _generateSchnorrAddr } from "./core";
import Schnorrkel from "./schnorrkel";
import { Key, PublicNonces, SignatureOutput } from "./types";

type Hex = string;

class SchnorrSigner {
  _privateKey: Key;
  _publicKey: Key;
  _schnorrkel: Schnorrkel;

  constructor(privateKey: Hex) {
    if (!isHexString(privateKey)) throw new Error("invalid hex for privateKey");

    this._privateKey = new Key(Buffer.from(privateKey.substring(2), "hex"));
    this._publicKey = new Key(
      Buffer.from(arrayify(computePublicKey(privateKey, true)))
    );
    this._schnorrkel = new Schnorrkel();
  }

  getPublicKey(): Key {
    return this._publicKey;
  }

  /**
   * This yields the schnorr address for a 1/1 setup.
   * If multisig, combine the public keys and use _generateSchnorrAddr manually
   *
   * @returns address
   */
  getSchnorrAddress() {
    return _generateSchnorrAddr(this._publicKey.buffer);
  }

  getPublicNonces(): PublicNonces {
    return this._schnorrkel.generateOrGetPublicNonces();
  }

  sign(commitment: string): SignatureOutput {
    return Schnorrkel.sign(this._privateKey, commitment);
  }

  mutliSignatureSign(
    msg: string,
    publicKeys: Key[],
    publicNonces: PublicNonces[]
  ) {
    return this._schnorrkel.multiSigSign(
      this._privateKey,
      msg,
      publicKeys,
      publicNonces
    );
  }

  /**
   * The onchain structure
   *
   * @param sigOutput
   * @returns hex forOnchainValidation
   */
  getEcrecoverSignature(sigOutput: SignatureOutput) {
    const publicKey = arrayify(this._publicKey.buffer);
    const px = publicKey.slice(1, 33);
    const parity = publicKey[0] - 2 + 27;
    return defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint8"],
      [px, sigOutput.challenge.buffer, sigOutput.signature.buffer, parity]
    );
  }
}

export default SchnorrSigner;
