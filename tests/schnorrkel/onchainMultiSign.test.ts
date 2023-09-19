import { describe, expect, it } from 'vitest'
import { ethers } from 'ethers'
import Schnorrkel from '../../src/index'
import { compile } from '../../utils/compile.js'
import { wallet2 } from '../config.js'
import DefaultSigner from '../../utils/DefaultSigner'
import { _generatePk } from '../../src/core'
const ERC1271_MAGICVALUE_BYTES32 = '0x1626ba7e'

describe('Multi Sign Tests', function () {

  async function deployContract(signerOne: any, signerTwo: any) {
    const SchnorrAccountAbstraction = compile('SchnorrAccountAbstraction')
    const factory = new ethers.ContractFactory(SchnorrAccountAbstraction.abi, SchnorrAccountAbstraction.bytecode, wallet2)

    // get the public key
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey([
      signerOne.getPublicKey(),
      signerTwo.getPublicKey()
    ])
    const px = ethers.utils.hexlify(combinedPublicKey.buffer.slice(1, 33))
    const combinedPublicAddress = '0x' + px.slice(px.length - 40, px.length)
    const contract: any = await factory.deploy([combinedPublicAddress])
    const isSigner = await contract.canSign(combinedPublicAddress)
    expect(isSigner).to.equal('0x0000000000000000000000000000000000000000000000000000000000000001')

    return { contract }
  }

  it('should generate a schnorr musig2 and validate it on the blockchain', async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)
    const { contract } = await deployContract(signerOne, signerTwo)

    const msg = 'just a test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const {signature: sigOne, challenge: e, finalPublicNonce} = signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)
    const {signature: sigTwo} = signerTwo.multiSignMessage(msgHash, publicKeys, publicNonces)
    const sSummed = Schnorrkel.sumSigs([sigOne, sigTwo])

    // the multisig px and parity
    const px = ethers.utils.hexlify(combinedPublicKey.buffer.slice(1, 33))
    const parity = combinedPublicKey.buffer[0] - 2 + 27

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder()
    const sigData = abiCoder.encode([ 'bytes32', 'bytes32', 'bytes32', 'uint8' ], [
      px,
      e.buffer,
      sSummed.buffer,
      parity
    ])
    const result = await contract.isValidSignature(msgHash, sigData)
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32)
  })

  it('should generate the same sig to be sure caching does not affect validation', async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)
    const { contract } = await deployContract(signerOne, signerTwo)

    const msg = 'just a test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const {signature: sigOne, challenge: e, finalPublicNonce} = signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)
    const {signature: sigTwo} = signerTwo.multiSignMessage(msgHash, publicKeys, publicNonces)
    const sSummed = Schnorrkel.sumSigs([sigOne, sigTwo])

    // the multisig px and parity
    const px = ethers.utils.hexlify(combinedPublicKey.buffer.slice(1, 33))

    const parity = combinedPublicKey.buffer[0] - 2 + 27

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder()
    const sigData = abiCoder.encode([ 'bytes32', 'bytes32', 'bytes32', 'uint8' ], [
      px,
      e.buffer,
      sSummed.buffer,
      parity
    ])
    const result = await contract.isValidSignature(msgHash, sigData)
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32)
  })

  it('should fail if the signer is totally different', async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)
    const { contract } = await deployContract(signerOne, signerTwo)

    const signerThree = new DefaultSigner(2)
    const msg = 'just a test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const publicKeys = [signerOne.getPublicKey(), signerThree.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerThree.getPublicNonces()]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)

//     finalPublicNonce: FinalPublicNonce, // the final public nonce
//   challenge: Challenge, // the schnorr challenge
//   signature: Signature, // the signature
    const {signature: sigOne, challenge: e} = signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)
    const {signature: sigTwo} = signerThree.multiSignMessage(msgHash, publicKeys, publicNonces)
    const sSummed = Schnorrkel.sumSigs([sigOne, sigTwo])

    // the multisig px and parity
    const px = combinedPublicKey.buffer.slice(1,33)
    const parity = combinedPublicKey.buffer[0] - 2 + 27

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder()
    const sigData = abiCoder.encode([ 'bytes32', 'bytes32', 'bytes32', 'uint8' ], [
      px,
      e.buffer,
      sSummed.buffer,
      parity
    ])
    const result = await contract.isValidSignature(msgHash, sigData)
    expect(result).to.equal('0xffffffff')
  })

  it('should fail if only one signature is provided', async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)
    const { contract } = await deployContract(signerOne, signerTwo)

    const msg = 'just a test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const {signature: sigOne, challenge: e} = signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)

    // the multisig px and parity
    const px = combinedPublicKey.buffer.slice(1,33)
    const parity = combinedPublicKey.buffer[0] - 2 + 27

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder()
    const sigData = abiCoder.encode([ 'bytes32', 'bytes32', 'bytes32', 'uint8' ], [
      px,
      e.buffer,
      sigOne.buffer,
      parity
    ])
    const result = await contract.isValidSignature(msgHash, sigData)
    expect(result).to.equal('0xffffffff')
  })

  it('should fail if a signer tries to sign twice with the same nonce', async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)
    await deployContract(signerOne, signerTwo)

    const msg = 'just a test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]    
    signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)
    expect(signerOne.multiSignMessage.bind(signerOne, msgHash, publicKeys, publicNonces)).to.throw('Nonces should be exchanged before signing')
  })

  it('should fail if only one signer tries to sign the transaction providing 2 messages', async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)
    const { contract } = await deployContract(signerOne, signerTwo)

    const msg = 'just a test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const publicKeys = [signerOne.getPublicKey(), signerTwo.getPublicKey()]
    const signerTwoNonces = signerTwo.getPublicNonces()
    const publicNonces = [signerOne.getPublicNonces(), signerTwoNonces]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const {signature: sigOne, challenge: e} = signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)
    const publicNoncesTwo = [signerOne.getPublicNonces(), signerTwoNonces]
    const {signature: sigTwo} = signerOne.multiSignMessage(msgHash, publicKeys, publicNoncesTwo)
    const sSummed = Schnorrkel.sumSigs([sigOne, sigTwo])

    // the multisig px and parity
    const px = combinedPublicKey.buffer.slice(1,33)
    const parity = combinedPublicKey.buffer[0] - 2 + 27

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder()
    const sigData = abiCoder.encode([ 'bytes32', 'bytes32', 'bytes32', 'uint8' ], [
      px,
      e.buffer,
      sSummed.buffer,
      parity
    ])
    const result = await contract.isValidSignature(msgHash, sigData)
    expect(result).to.equal('0xffffffff')
  })

  it('should successfully pass even if the order of the public keys is different', async function () {
    // deploy the contract
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)
    const { contract } = await deployContract(signerOne, signerTwo)

    const msg = 'just a test message'
    const msgHash = ethers.utils.solidityKeccak256(['string'], [msg])
    const publicKeys = [signerTwo.getPublicKey(), signerOne.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const {signature: sigOne, challenge: e} = signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)
    const {signature: sigTwo} = signerTwo.multiSignMessage(msgHash, publicKeys, publicNonces)
    const sSummed = Schnorrkel.sumSigs([sigOne, sigTwo])

    // the multisig px and parity
    const px = combinedPublicKey.buffer.slice(1,33)
    const parity = combinedPublicKey.buffer[0] - 2 + 27

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder()
    const sigData = abiCoder.encode([ 'bytes32', 'bytes32', 'bytes32', 'uint8' ], [
      px,
      e.buffer,
      sSummed.buffer,
      parity
    ])
    const result = await contract.isValidSignature(msgHash, sigData)
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32)
  })

  it('should throw error requirements for public keys when generating nonces and multi singatures', async function () {
    // chai.Assertion.expectExpects(3)
    const signerOne = new DefaultSigner(0)
    const signerTwo = new DefaultSigner(1)

    try {
        Schnorrkel.getCombinedPublicKey([signerTwo.getPublicKey()])
    } catch (e: any) {
      expect(e.message).to.equal('At least 2 public keys should be provided')
    }
    try {
        Schnorrkel.getCombinedAddress([signerOne.getPublicKey()])
    } catch (e: any) {
      expect(e.message).to.equal('At least 2 public keys should be provided')
    }

    const msgHash = ethers.utils.hashMessage('just a test message')
    const publicKeys = [signerOne.getPublicKey()]
    const publicNonces = [signerOne.getPublicNonces(), signerTwo.getPublicNonces()]
    try {
      signerOne.multiSignMessage(msgHash, publicKeys, publicNonces)
    } catch (e: any) {
      expect(e.message).to.equal('At least 2 public keys should be provided')
    }
  })
})