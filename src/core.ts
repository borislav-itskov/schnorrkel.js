import { randomBytes } from 'crypto'
import secp256k1 from 'secp256k1'

import { KeyPair } from './keys'

class Schnorrkel {
  static gererateRandomKeys(): KeyPair {
    let privKeyBytes: Buffer | undefined
    do {
      privKeyBytes = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privKeyBytes))

    const pubKey = Buffer.from(secp256k1.publicKeyCreate(privKeyBytes))

    return new KeyPair({
      publicKey: pubKey,
      privateKey: privKeyBytes,
    })
  }
}

export default Schnorrkel