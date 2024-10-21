import { describe, expect, it } from "vitest";
import { ethers } from "ethers";
import SchnorrSigner from "../../src/signers/schnorrSigner.js";
import { compile } from "../../utils/compile.js";
import { pk1, wallet } from "../config.js";

const ERC1271_MAGICVALUE_BYTES32 = "0x1626ba7e";

describe("Single Sign Tests", function () {
  async function deployContract() {
    const SchnorrAccountAbstraction = compile("SchnorrAccountAbstraction");

    // get the schnorr addr
    const signer = new SchnorrSigner(pk1);
    const schnorrAddr = signer.getSchnorrAddress();

    // deploying the contract
    const factory = new ethers.ContractFactory(
      SchnorrAccountAbstraction.abi,
      SchnorrAccountAbstraction.bytecode,
      wallet
    );
    const contract: any = await factory.deploy([schnorrAddr]);
    const isSigner = await contract.canSign(schnorrAddr);
    expect(isSigner).to.equal(
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    );

    return { contract };
  }

  it("should generate a schnorr signature and verify onchain", async function () {
    const { contract } = await deployContract();

    // sign
    const msg = "just a test message";
    const msgHash = ethers.utils.hashMessage(msg);
    const signer = new SchnorrSigner(pk1);
    const sig = signer.sign(msgHash);
    const result = await contract.isValidSignature(
      msgHash,
      signer.getEcrecoverSignature(sig)
    );
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  });
});
