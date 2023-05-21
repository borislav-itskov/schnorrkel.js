import Key from './key'

class KeyPair {
    privateKey: Key
    publicKey: Key

    constructor({ publicKey, privateKey }: { publicKey: Buffer, privateKey: Buffer }) {
        this.privateKey = new Key(privateKey)
        this.publicKey = new Key(publicKey)
    }

    static fromJson(params: { publicKey: Buffer, privateKey: Buffer }): KeyPair {
        return new KeyPair(params)
    }
}

export default KeyPair