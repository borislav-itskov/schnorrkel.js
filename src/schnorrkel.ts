import { KeyPair } from './keys'
import { _generateRandomKeys } from './core'

class Schnorrkel {
  static generateRandomKeys(): KeyPair {
    return _generateRandomKeys()
  }
}

export default Schnorrkel