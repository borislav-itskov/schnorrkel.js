import { describe, expect, it } from 'vitest'
import secp256k1 from 'secp256k1'
import { ethers } from 'ethers'
import Schnorrkel, { Key } from '../../src/index'
import SchnorrSigner from '../../src/schnorrSigner.js'
import { compile } from '../../utils/compile.js'
import { pk1, wallet } from '../config.js'

const ERC1271_MAGICVALUE_BYTES32 = '0x1626ba7e'

describe('Single Sign Tests', function () {
  async function deployContract() {
    const SchnorrAccountAbstraction = compile('SchnorrAccountAbstraction')

    // the eth address
    const publicKey = secp256k1.publicKeyCreate(ethers.utils.arrayify(pk1))
    const px = publicKey.slice(1, 33)
    const pxGeneratedAddress = ethers.utils.hexlify(px)
    const address = '0x' + pxGeneratedAddress.slice(pxGeneratedAddress.length - 40, pxGeneratedAddress.length)

    // deploying the contract
    const factory = new ethers.ContractFactory(SchnorrAccountAbstraction.abi, SchnorrAccountAbstraction.bytecode, wallet)
    const contract: any = await factory.deploy([address])
    const isSigner = await contract.canSign(address)
    expect(isSigner).to.equal('0x0000000000000000000000000000000000000000000000000000000000000001')

    return { contract }
  }

  it('should generate a schnorr signature and verify onchain', async function () {
    const { contract } = await deployContract()

    // sign
    const msg = 'just a test message'
    const msgHash = ethers.utils.hashMessage(msg)
    const signer = new SchnorrSigner(pk1)
    const sig = signer.sign(msgHash)
    const result = await contract.isValidSignature(msgHash, signer.getEcrecoverStructure(sig))
    expect(result).to.equal(ERC1271_MAGICVALUE_BYTES32)
  })
})