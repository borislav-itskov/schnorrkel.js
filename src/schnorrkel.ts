import secp256k1 from 'secp256k1'

import { KeyPair, Key } from './keys'
import { _generateL, _generateRandomKeys, _aCoefficient } from './core'

class Schnorrkel {
  static getCombinedPublicKey(publicKeys: Array<Key>): Key {
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
}

export default Schnorrkel