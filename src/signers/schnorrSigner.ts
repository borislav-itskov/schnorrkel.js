import { arrayify, computePublicKey, isHexString } from "ethers/lib/utils";
import { _generateSchnorrAddr } from "../core";
import Schnorrkel from "../schnorrkel";
import { Key, PublicNonces, SignatureOutput } from "../types";
import SchnorrProvider from "../providers/schnorrProvider";

type Hex = string;

class SchnorrSigner extends SchnorrProvider {
  private _privateKey: Key;

  constructor(privateKeyHex: Hex) {
    if (!isHexString(privateKeyHex))
      throw new Error("invalid hex for privateKey");

    super(
      new Key(Buffer.from(arrayify(computePublicKey(privateKeyHex, true))))
    );

    this._privateKey = new Key(Buffer.from(privateKeyHex.substring(2), "hex"));
  }

  sign(commitment: string): SignatureOutput;
  sign(
    commitment: string,
    publicKeys: Key[],
    publicNonces: PublicNonces[]
  ): SignatureOutput;
  sign(
    commitment: string,
    publicKeys?: Key[],
    publicNonces?: PublicNonces[]
  ): SignatureOutput {
    if (publicKeys && publicNonces) {
      return this._schnorrkel.multiSigSign(
        this._privateKey,
        commitment,
        publicKeys,
        publicNonces
      );
    }

    return Schnorrkel.sign(this._privateKey, commitment);
  }
}

export default SchnorrSigner;
