const { ethers } = require('ethers')
const secp256k1 = require('secp256k1')
const { randomBytes } = require('crypto');

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

    return sigData
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

function verify() {
    // TODO
    return true
}

module.exports = {
	sign,
	verify
}
