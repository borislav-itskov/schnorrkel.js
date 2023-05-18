import { Schnorrkel } from "..";
const schnorrkel = new Schnorrkel()

const { ethers } = require("hardhat");
const ERC1271_MAGICVALUE_BYTES32 = "0x1626ba7e";
const DefaultSigner = require('../signers/DefaultSigner')

const {
  loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");

describe("Multi Sign Tests", function () {
  const entryPoint = "0x0000000000000000000000000000000000000000";
  async function deployContract() {

    // Contracts are deployed using the first signer/account by default
    const SchnorrAccountAbstraction = await ethers.getContractFactory("SchnorrAccountAbstraction");

    // get the public key
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const combinedPublicAddress = schnorrkel.getCombinedAddress([
      signerOne.getPublicKey(),
      signerTwo.getPublicKey()
    ]);
    const contract = await SchnorrAccountAbstraction.deploy(entryPoint, [combinedPublicAddress]);
    const isSigner = await contract.canSign(combinedPublicAddress);
    expect(isSigner).to.equal('0x0000000000000000000000000000000000000000000000000000000000000001');

    return { contract };
  }

  it("should generate a schnorr musig2 and validate it on the blockchain", async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const { contract } = await loadFixture(deployContract);

    const msg = 'just a test message';
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)
    const {s: sigOne, e} = signerOne.multiSignMessage(msg, publicKeys, publicNonces)
    const {s: sigTwo} = signerTwo.multiSignMessage(msg, publicKeys, publicNonces)
    const sSummed = schnorrkel.sumSigs([sigOne, sigTwo]);

    // the multisig px and parity
    const px = combinedPublicKey.slice(1,33);
    const parity = combinedPublicKey[0] - 2 + 27;

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      px,
      e,
      sSummed,
      parity
    ]);
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const result = await contract.isValidSignature(msgHash, sigData);
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  })

  it("should fail if the signer is totally different", async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const { contract } = await loadFixture(deployContract);

    const signerThree = new DefaultSigner(2);
    const msg = 'just a test message';
    const publicKeys = [signerOne.getPublicKey(), signerThree.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerThree.getPublicNonces()]
    const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)
    const {s: sigOne, e} = signerOne.multiSignMessage(msg, publicKeys, publicNonces)
    const {s: sigTwo} = signerThree.multiSignMessage(msg, publicKeys, publicNonces)
    const sSummed = schnorrkel.sumSigs([sigOne, sigTwo]);

    // the multisig px and parity
    const px = combinedPublicKey.slice(1,33);
    const parity = combinedPublicKey[0] - 2 + 27;

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      px,
      e,
      sSummed,
      parity
    ]);
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const result = await contract.isValidSignature(msgHash, sigData);
    expect(result).to.equal('0xffffffff');
  })

  it("should fail if only one signature is provided", async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const { contract } = await loadFixture(deployContract);

    const msg = 'just a test message';
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)
    const {s: sigOne, e} = signerOne.multiSignMessage(msg, publicKeys, publicNonces)

    // the multisig px and parity
    const px = combinedPublicKey.slice(1,33);
    const parity = combinedPublicKey[0] - 2 + 27;

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      px,
      e,
      sigOne,
      parity
    ]);
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const result = await contract.isValidSignature(msgHash, sigData);
    expect(result).to.equal('0xffffffff');
  })  

  it("should fail if a signer tries to sign twice with the same nonce", async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const { contract } = await loadFixture(deployContract);

    const msg = 'just a test message';
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]    
    const {s, e} = signerOne.multiSignMessage(msg, publicKeys, publicNonces)
    expect(signerOne.multiSignMessage.bind(signerOne, msg, publicKeys, publicNonces)).to.throw('Nonces should be exchanged before signing');
  })

  it("should fail if only one signer tries to sign the transaction providing 2 messages", async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const { contract } = await loadFixture(deployContract);

    const msg = 'just a test message';
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const signerTwoNonces = signerTwo.getPublicNonces();
    const publicNonces = [signerOne.getPublicNonces(), signerTwoNonces]
    const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)
    const {s: sigOne, e} = signerOne.multiSignMessage(msg, publicKeys, publicNonces)
    const publicNoncesTwo = [signerOne.getPublicNonces(), signerTwoNonces]
    const {s: sigTwo} = signerOne.multiSignMessage(msg, publicKeys, publicNoncesTwo)
    const sSummed = schnorrkel.sumSigs([sigOne, sigTwo]);

    // the multisig px and parity
    const px = combinedPublicKey.slice(1,33);
    const parity = combinedPublicKey[0] - 2 + 27;

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      px,
      e,
      sSummed,
      parity
    ]);
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const result = await contract.isValidSignature(msgHash, sigData);
    expect(result).to.equal('0xffffffff');
  })

  it("should generate a schnorr musig2 and validate it offchain", async function () {
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const msg = 'just a test message';
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)
    const {s: sigOne, R} = signerOne.multiSignMessage(msg, publicKeys, publicNonces)
    const {s: sigTwo} = signerTwo.multiSignMessage(msg, publicKeys, publicNonces)
    const sSummed = schnorrkel.sumSigs([sigOne, sigTwo]);
    const result = schnorrkel.verify(sSummed, msg, R, combinedPublicKey);
    expect(result).to.equal(true);
  })

  it("should successfully pass even if the order of the public keys is different", async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0);
    const signerTwo = new DefaultSigner(1);
    const { contract } = await loadFixture(deployContract);

    const msg = 'just a test message';
    const publicKeys = [signerTwo.getPublicKey(), signerOne.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)
    const {s: sigOne, e} = signerOne.multiSignMessage(msg, publicKeys, publicNonces)
    const {s: sigTwo} = signerTwo.multiSignMessage(msg, publicKeys, publicNonces)
    const sSummed = schnorrkel.sumSigs([sigOne, sigTwo]);

    // the multisig px and parity
    const px = combinedPublicKey.slice(1,33);
    const parity = combinedPublicKey[0] - 2 + 27;

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder();
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
      px,
      e,
      sSummed,
      parity
    ]);
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
    const result = await contract.isValidSignature(msgHash, sigData);
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32);
  })
});
