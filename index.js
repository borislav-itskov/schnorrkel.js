const { ethers } = require('ethers')
const secp256k1 = require('secp256k1')
const { randomBytes } = require('crypto');
const EC = require('elliptic').ec;
const ec = new EC('secp256k1');
const generatorPoint = ec.g;

function hashMessage(message) {
    return ethers.utils.solidityKeccak256(['string'], [message])
}

function sign(message, privateKey) {
    const publicKey = secp256k1.publicKeyCreate(privateKey)
    const msgHash = hashMessage(message)

    const sig = signRaw(msgHash, privateKey)

    const px = publicKey.slice(1, 33)
    const parity = publicKey[0] - 2 + 27

    // wrap the result
    const abiCoder = new ethers.utils.AbiCoder()
    const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
        px,
        sig.e,
        sig.s,
        parity
    ])


    return {
        h: msgHash,
        s: sigData,
        r: sig.R
    }
}

function signRaw(msgHash, privateKey) {
    const publicKey = secp256k1.publicKeyCreate(privateKey)

    // R = G * k
    var k = randomBytes(32)
    var R = secp256k1.publicKeyCreate(k)

    // e = h(address(R) || compressed pubkey || m)
    var e = challenge(R, msgHash, publicKey)

    // xe = x * e
    var xe = secp256k1.privateKeyTweakMul(privateKey, e)

    // s = k + xe
    var s = secp256k1.privateKeyTweakAdd(k, xe)

    return {R, s, e}
}

function challenge(R, m, publicKey) {
    // convert R to address
    // see https://github.com/ethereum/go-ethereum/blob/eb948962704397bb861fd4c0591b5056456edd4d/crypto/crypto.go#L275
    var R_uncomp = secp256k1.publicKeyConvert(R, false);
    var R_addr = ethers.utils.arrayify(ethers.utils.keccak256(R_uncomp.slice(1, 65))).slice(12, 32)

    // e = keccak256(address(R) || compressed publicKey || m)
    return ethers.utils.arrayify(
        ethers.utils.solidityKeccak256(
            ["address", "uint8", "bytes32", "bytes32"],
            [R_addr, publicKey[0] + 27 - 2, publicKey.slice(1, 33), m]
        )
    )
}

function verify(signature, hash, R, publicKey) {
    const abiCoder = new ethers.utils.AbiCoder()
    const [px, e, s, parity] = abiCoder.decode([ "bytes32", "bytes32", "bytes32", "uint8" ], signature)

    console.log(`verify e decoded: ${ethers.utils.arrayify(e)}`)
    const eC = challenge(R, hash, publicKey)
    console.log(`verify e recalced: ${eC}`)

    // const sG = secp256k1.publicKeyCreate(ethers.utils.arrayify(s), false)
    // console.log(`verify sG: ${sG}`)

    // console.log(R.length, publicKey.length, eC.length)
    // const Pe = secp256k1.publicKeyTweakMul(publicKey, eC, false)
    // console.log(Pe.length)
    // const RplusPe = secp256k1.publicKeyTweakAdd(R, Pe.slice(1,33), false)
    // console.log(`verify RplusPe: ${RplusPe}`)

    const sG = generatorPoint.mul(ethers.utils.arrayify(s))
    console.log(`verify sG: ${sG.encode()}`)

    const P = ec.keyFromPublic(publicKey).getPublic()
    // console.log(`verify P: ${P.encode()}`)
    const Pe = P.mul(eC)
    // console.log(`verify Pe: ${Pe.encode()}`)

    R = ec.keyFromPublic(R).getPublic()
    const RplusPe = R.add(Pe)
    console.log(`verify RplusPe: ${RplusPe.encode()}`)

    return sG.eq(RplusPe)
}

function test() {
    // const wallet = ethers.Wallet.fromMnemonic("")
    // const privateKey = ethers.utils.arrayify(wallet.privateKey);
    const wallet = new ethers.Wallet('d6c4c7b36b37906a95e54b426332c8d919c929cf8807000fcf1cfb81b29a202e')

    const privateKey = ethers.utils.arrayify(wallet.privateKey)
    const publicKey = secp256k1.publicKeyCreate(privateKey)

    const msg = 'sign me'
    const sigResult = sign(msg, privateKey)

    console.log(`hash: ${sigResult.h}`)
    console.log(`signature: ${sigResult.s}`)

    const res = verify(sigResult.s, sigResult.h, sigResult.r, publicKey)
    console.log(`result: ${res}`)
}

test()

module.exports = {
    sign,
	verify
}
