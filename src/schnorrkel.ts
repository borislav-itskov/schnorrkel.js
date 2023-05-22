import secp256k1 from 'secp256k1'

import { KeyPair, Key } from './keys'
import type { Nonces, PublicNonces } from './nonce'
import type { Signature } from './signature'

import { _generateL, _generateRandomKeys, _aCoefficient, _generatePublicNonces, _multiSigSign, _hashPrivateKey, _sumSigs } from './core'

class Schnorrkel {
  private nonces: Nonces = {}

  private _setNonce(privateKey: Buffer): string {
    const { publicNonceData, privateNonceData, hash } = _generatePublicNonces(privateKey)
    this.nonces[hash] = { ...privateNonceData, ...publicNonceData }
    return hash
  }

  static getCombinedPublicKey(publicKeys: Array<Key>): Key {
    if (publicKeys.length < 2) {
      throw Error('At least 2 public keys should be provided')
    }

    const bufferPublicKeys = publicKeys.map(publicKey => publicKey.buffer)
    const L = _generateL(bufferPublicKeys)

    const modifiedKeys = bufferPublicKeys.map(publicKey => {
      return secp256k1.publicKeyTweakMul(publicKey, _aCoefficient(publicKey, L))
    })

    return new Key(Buffer.from(secp256k1.publicKeyCombine(modifiedKeys)))
  }

  static generateRandomKeys(): KeyPair {
    return _generateRandomKeys()
  }

  static fromJson(json: string): Schnorrkel {
    interface JsonData {
      nonces: {
        [hash: string]: {
          k: string,
          kTwo: string,
          kPublic: string,
          kTwoPublic: string,
        }
      }
    }
    try {
      const jsonData = JSON.parse(json) as JsonData
      const noncesEntries = Object.entries(jsonData.nonces).map(([hash, nonce]) => {
        return [
          hash,
          {
            k: Key.fromHex(nonce.k),
            kTwo: Key.fromHex(nonce.kTwo),
            kPublic: Key.fromHex(nonce.kPublic),
            kTwoPublic: Key.fromHex(nonce.kTwoPublic),
          }
        ]
      })

      const schnorrkel = new Schnorrkel()
      schnorrkel.nonces = Object.fromEntries(noncesEntries)
      return schnorrkel
    } catch (error) {
      throw new Error('Invalid JSON')
    }
  }

  generatePublicNonces(privateKey: Key): PublicNonces {
    const hash = this._setNonce(privateKey.buffer)
    const nonce = this.nonces[hash]

    return {
      kPublic: nonce.kPublic,
      kTwoPublic: nonce.kTwoPublic,
    }
  }

  toJson() {
    const nonces = Object.fromEntries(Object.entries(this.nonces).map(([hash, nonce]) => {
      return [
        hash,
        {
          k: nonce.k.toHex(),
          kTwo: nonce.kTwo.toHex(),
          kPublic: nonce.kPublic.toHex(),
          kTwoPublic: nonce.kTwoPublic.toHex(),
        }
      ]
    }))

    return JSON.stringify({
      nonces,
    })
  }

  private clearNonces(privateKey: Key): void {
    const x = privateKey.buffer
    const hash = _hashPrivateKey(x)

    delete this.nonces[hash]
  }

  multiSigSign(privateKey: Key, msg: string, publicKeys: Key[], publicNonces: PublicNonces[]): Signature {
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const signature = _multiSigSign(this.nonces, combinedPublicKey, privateKey.buffer, msg, publicKeys.map(key => key.buffer), publicNonces)

    // absolutely crucial to delete the nonces once a signature has been crafted with them.
    // nonce reusae will lead to private key leakage!
    this.clearNonces(privateKey)

    return signature
  }

  static sumSigs(signatures: Uint8Array[]): Buffer {
    return _sumSigs(signatures)
  }
}

export default Schnorrkel