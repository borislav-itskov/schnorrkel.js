import { describe, expect, it } from "vitest";
import { ContractFactory } from "ethers";
import Schnorrkel from "../../src/index";
import { compile } from "../../utils/compile";
import { pk1, pk2, pk3, wallet2 } from "../config";
import SchnorrSigner from "../../src/signers/schnorrSigner";
import SchnorrMultisigProvider from "../../src/providers/schnorrMultisigProvider";
import {
  defaultAbiCoder,
  hashMessage,
  solidityKeccak256,
} from "ethers/lib/utils";
const ERC1271_MAGICVALUE_BYTES32 = "0x1626ba7e";

describe("Multi Sign Tests", function () {
  async function deployContract(multisigProvider: SchnorrMultisigProvider) {
    const SchnorrAccountAbstraction = compile("SchnorrAccountAbstraction");
    const factory = new ContractFactory(
      SchnorrAccountAbstraction.abi,
      SchnorrAccountAbstraction.bytecode,
      wallet2
    );
    const schnorrAddr = multisigProvider.getSchnorrAddress();
    const contract: any = await factory.deploy([schnorrAddr]);
    const isSigner = await contract.canSign(schnorrAddr);
    expect(isSigner).to.equal(
      "0x0000000000000000000000000000000000000000000000000000000000000001"
    );

    return { contract };
  }

  it("should generate a schnorr musig2 and validate it on the blockchain", async function () {
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);
    const multisigProvider = new SchnorrMultisigProvider([
      signerOne,
      signerTwo,
    ]);
    const { contract } = await deployContract(multisigProvider);

    const msg = "just a test message";
    const msgHash = solidityKeccak256(["string"], [msg]);
    const publicNonces = multisigProvider.getPublicNonces();
    const signature = signerOne.sign(
      msgHash,
      multisigProvider.getPublicKeys(),
      publicNonces
    );
    const signatureTwo = signerTwo.sign(
      msgHash,
      multisigProvider.getPublicKeys(),
      publicNonces
    );
    const result = await contract.isValidSignature(
      msgHash,
      multisigProvider.getEcrecoverSignature([signature, signatureTwo])
    );
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  });

  it("should generate the same sig to be sure caching does not affect validation", async function () {
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);
    const multisigProvider = new SchnorrMultisigProvider([
      signerOne,
      signerTwo,
    ]);
    const { contract } = await deployContract(multisigProvider);

    const msg = "just a test message";
    const msgHash = solidityKeccak256(["string"], [msg]);
    const publicKeys = multisigProvider.getPublicKeys();
    const publicNonces = multisigProvider.getPublicNonces();
    const signature = signerOne.sign(msgHash, publicKeys, publicNonces);
    const signatureTwo = signerTwo.sign(msgHash, publicKeys, publicNonces);
    const result = await contract.isValidSignature(
      msgHash,
      multisigProvider.getEcrecoverSignature([signature, signatureTwo])
    );
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  });

  it("should fail if the signer is totally different", async function () {
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);
    const multisigProvider = new SchnorrMultisigProvider([
      signerOne,
      signerTwo,
    ]);
    const { contract } = await deployContract(multisigProvider);

    const signerThree = new SchnorrSigner(pk3);
    const multisigProviderAttacker = new SchnorrMultisigProvider([
      signerOne,
      signerThree,
    ]);
    const msg = "just a test message";
    const msgHash = solidityKeccak256(["string"], [msg]);
    const publicKeys = multisigProviderAttacker.getPublicKeys();
    const publicNonces = multisigProviderAttacker.getPublicNonces();

    const signature = signerOne.sign(msgHash, publicKeys, publicNonces);
    const signatureTwo = signerThree.sign(msgHash, publicKeys, publicNonces);
    const result = await contract.isValidSignature(
      msgHash,
      multisigProviderAttacker.getEcrecoverSignature([signature, signatureTwo])
    );
    expect(result).to.equal("0xffffffff");
  });

  it("should fail if only one signature is provided", async function () {
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);
    const multisigProvider = new SchnorrMultisigProvider([
      signerOne,
      signerTwo,
    ]);
    const { contract } = await deployContract(multisigProvider);

    const msg = "just a test message";
    const msgHash = solidityKeccak256(["string"], [msg]);
    const publicKeys = multisigProvider.getPublicKeys();
    const publicNonces = multisigProvider.getPublicNonces();
    const signature = signerOne.sign(msgHash, publicKeys, publicNonces);

    try {
      multisigProvider.getEcrecoverSignature([signature]);
    } catch (e: any) {
      expect(e.message).to.equal(
        "Expected at least 2 signatures for aggregation"
      );
    }

    const result = await contract.isValidSignature(
      msgHash,
      signerOne.getEcrecoverSignature(signature)
    );
    expect(result).to.equal("0xffffffff");
  });

  it("should fail if a signer tries to sign twice with the same nonce", async function () {
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);
    const multisigProvider = new SchnorrMultisigProvider([
      signerOne,
      signerTwo,
    ]);

    const msg = "just a test message";
    const msgHash = solidityKeccak256(["string"], [msg]);
    const publicKeys = multisigProvider.getPublicKeys();
    expect(signerOne.sign.bind(signerOne, msgHash, publicKeys, [])).to.throw(
      "Nonces should be exchanged before signing"
    );
  });

  it("should fail if only one signer tries to sign the transaction providing 2 different public nonces", async function () {
    // deploy the contract
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);
    const multisigProvider = new SchnorrMultisigProvider([
      signerOne,
      signerTwo,
    ]);
    const { contract } = await deployContract(multisigProvider);

    const msg = "just a test message";
    const msgHash = solidityKeccak256(["string"], [msg]);
    const publicKeys = multisigProvider.getPublicKeys();
    const signature = signerOne.sign(
      msgHash,
      publicKeys,
      multisigProvider.getPublicNonces()
    );
    const signatreTwo = signerOne.sign(
      msgHash,
      publicKeys,
      multisigProvider.getPublicNonces()
    );
    const result = await contract.isValidSignature(
      msgHash,
      multisigProvider.getEcrecoverSignature([signature, signatreTwo])
    );
    expect(result).to.equal("0xffffffff");
  });

  it("should successfully pass even if the order of the public keys is different", async function () {
    // deploy the contract
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);
    const multisigProvider = new SchnorrMultisigProvider([
      signerOne,
      signerTwo,
    ]);
    const { contract } = await deployContract(multisigProvider);

    const msg = "just a test message";
    const msgHash = solidityKeccak256(["string"], [msg]);
    const publicKeys = [signerTwo.publicKey, signerOne.publicKey];
    const publicNonces = multisigProvider.getPublicNonces();
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys);
    const { signature: sigOne, challenge: e } = signerOne.sign(
      msgHash,
      publicKeys,
      publicNonces
    );
    const { signature: sigTwo } = signerTwo.sign(
      msgHash,
      publicKeys,
      publicNonces
    );
    const sSummed = Schnorrkel.sumSigs([sigOne, sigTwo]);

    // the multisig px and parity
    const px = combinedPublicKey.buffer.slice(1, 33);
    const parity = combinedPublicKey.buffer[0] - 2 + 27;

    // wrap the result
    const sigData = defaultAbiCoder.encode(
      ["bytes32", "bytes32", "bytes32", "uint8"],
      [px, e.buffer, sSummed.buffer, parity]
    );
    const result = await contract.isValidSignature(msgHash, sigData);
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  });

  it("should throw error requirements for public keys when generating nonces and multi singatures", async function () {
    const signerOne = new SchnorrSigner(pk1);
    const signerTwo = new SchnorrSigner(pk2);

    try {
      Schnorrkel.getCombinedPublicKey([signerTwo.publicKey]);
    } catch (e: any) {
      expect(e.message).to.equal("At least 2 public keys should be provided");
    }
    try {
      Schnorrkel.getCombinedAddress([signerOne.publicKey]);
    } catch (e: any) {
      expect(e.message).to.equal("At least 2 public keys should be provided");
    }

    const msgHash = hashMessage("just a test message");
    const publicKeys = [signerOne.publicKey];
    const publicNonces = [
      signerOne.getPublicNonces(),
      signerTwo.getPublicNonces(),
    ];
    try {
      signerOne.sign(msgHash, publicKeys, publicNonces);
    } catch (e: any) {
      expect(e.message).to.equal("At least 2 public keys should be provided");
    }
  });
});
