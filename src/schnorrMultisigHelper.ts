import { arrayify, defaultAbiCoder } from "ethers/lib/utils";
import { _generateSchnorrAddr } from "./core";
import Schnorrkel from "./schnorrkel";
import { Key, SignatureOutput } from "./types";

class SchnorrMultisigHelper {
  _publicKeys: Key[];

  constructor(publicKeys: Key[]) {
    this._publicKeys = publicKeys;
  }

  getSchnorrAddress() {
    return _generateSchnorrAddr(
      Schnorrkel.getCombinedPublicKey(this._publicKeys).buffer
    );
  }

  getEcrecoverSignature(sigOutputs: SignatureOutput[]) {
    const publicKey = arrayify(
      Schnorrkel.getCombinedPublicKey(this._publicKeys).buffer
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

export default SchnorrMultisigHelper;
