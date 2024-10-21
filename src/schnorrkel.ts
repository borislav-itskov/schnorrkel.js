import secp256k1 from 'secp256k1'

import { Key, Nonces, PublicNonces, Signature, NoncePairs } from './types'

import { _generateL, _aCoefficient, _generateNonces, _multiSigSign, _hashPrivateKey, _sumSigs, _verify, _generateSchnorrAddr, _sign } from './core'
import { InternalNonces, InternalPublicNonces } from './core/types'
import { Challenge, PublicNonce, SignatureOutput } from './types/signature'
import { hexlify, randomBytes } from 'ethers/lib/utils'

class Schnorrkel {
  protected nonces: Nonces = {}
  private readonly nonceId: string = hexlify(randomBytes(32))

  /**
   * Set the nonces for the next multisignature.
   * Nonces should not be manipulated outside the library. Also,
   * they should be completely random.
   */
  private setNonce(): void {
    const { publicNonceData, privateNonceData } = _generateNonces()

    const mappedPublicNonce: PublicNonces = {
      kPublic: new Key(Buffer.from(publicNonceData.kPublic)),
      kTwoPublic: new Key(Buffer.from(publicNonceData.kTwoPublic)),
    }

    const mappedPrivateNonce: Pick<NoncePairs, 'k' | 'kTwo'> = {
      k: new Key(Buffer.from(privateNonceData.k)),
      kTwo: new Key(Buffer.from(privateNonceData.kTwo))
    }

    this.nonces[this.nonceId] = { ...mappedPrivateNonce, ...mappedPublicNonce }
  }

  /**
   * Clear the nonces used in the last signature
   * This is a very important step as otherwise, we go into nonce
   * reuse scenario
   */
  private clearNonces(): void {
    // this shouldn't happen, just extra safety
    // clearNonces should be called after a signature has been crafted.
    // If the hash is not found in the nonces by any chance after
    // a signature, then the process should be stopped as we don't
    // know nonces have been used for the signature
    if (! this.nonces[this.nonceId]) {
      throw new Error('Multisignature nonces not found')
    }

    delete this.nonces[this.nonceId]
  }

  private getMappedPublicNonces(publicNonces: PublicNonces[]): InternalPublicNonces[] {
    return publicNonces.map(publicNonce => {
      return {
        kPublic: publicNonce.kPublic.buffer,
        kTwoPublic: publicNonce.kTwoPublic.buffer,
      }
    })
  }

  private getMappedNonces(): InternalNonces {
    if (!this.nonces[this.nonceId]) {
      return {}
    }

    return {
      [this.nonceId]: {
        k: this.nonces[this.nonceId].k.buffer,
        kTwo: this.nonces[this.nonceId].kTwo.buffer,
        kPublic: this.nonces[this.nonceId].kPublic.buffer,
        kTwoPublic: this.nonces[this.nonceId].kTwoPublic.buffer,
      }
    }
  }

  /**
   * Sum the public keys in a safe manner with a specific
   * _aCoefficient for each publicKey
   *
   * @param publicKeys - the signers
   * @returns Key summed public key
   */
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

  /**
   * The address returned by ecrecover on-chain schnorr verification
   * for the given public keys
   * @param publicKeys
   * @returns string address
   */
  static getCombinedAddress(publicKeys: Array<Key>): string {
    if (publicKeys.length < 2) {
      throw Error('At least 2 public keys should be provided')
    }

    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    return _generateSchnorrAddr(combinedPublicKey.buffer)
  }

  /**
   * Generate nonces for the next signature if there aren't any.
   * If there are, just return them.
   * This is a method you should use if you don't want to manage
   * the nonces yourself
   *
   * @returns PublicNonces
   */
  generateOrGetPublicNonces(): PublicNonces {
    if (this.hasNonces()) {
      return this.getPublicNonces()
    }

    return this.generatePublicNonces()
  }

  /**
   * Genetate the nonces and return the public ones for a multisignature.
   * This method always generates new nonces. If you want to keep
   * you state, you should check with hasNonces() whether they are set.
   * You need to maintain the state for the nonce exchanging phase and
   * the signing phase
   *
   * @returns PublicNonces
   */
  generatePublicNonces(): PublicNonces {
    this.setNonce()
    const nonce = this.nonces[this.nonceId]

    return {
      kPublic: nonce.kPublic,
      kTwoPublic: nonce.kTwoPublic,
    }
  }

  /**
   * Get the public nonces.
   * If none are set, an error is returned
   *   
   * @returns PublicNonces
   */
  getPublicNonces(): PublicNonces {
    const nonce = this.nonces[this.nonceId]

    if (!nonce) {
      throw new Error('Nonces not set')
    }

    return {
      kPublic: nonce.kPublic,
      kTwoPublic: nonce.kTwoPublic,
    }
  }

  hasNonces(): boolean {
    return this.nonceId in this.nonces
  }

  /**
   * Compute a multisignature.
   * The nonce exchange phase should have passed before this stage
   *
   * @param privateKey - the key you're signing with
   * @param hash - the message of the multisignature
   * @param publicKeys - the participants
   * @param publicNonces - the public nonces of the participants
   * @returns SignatureOutput
   */
  multiSigSign(privateKey: Key, hash: string, publicKeys: Key[], publicNonces: PublicNonces[]): SignatureOutput {
    const combinedPublicKey = Schnorrkel.getCombinedPublicKey(publicKeys)
    const mappedPublicNonce = this.getMappedPublicNonces(publicNonces)
    const mappedNonces = this.getMappedNonces()

    const musigData = _multiSigSign(this.nonceId, mappedNonces, combinedPublicKey.buffer, privateKey.buffer, hash, publicKeys.map(key => key.buffer), mappedPublicNonce)

    // absolutely crucial to delete the nonces once a signature has been crafted.
    // nonce reuse will lead to private key leakage!
    this.clearNonces()

    return {
      signature: new Signature(Buffer.from(musigData.signature)),
      publicNonce: new PublicNonce(Buffer.from(musigData.publicNonce)),
      challenge: new Challenge(Buffer.from(musigData.challenge)),
    }
  }

  /**
   * Compute a single schnorr signature
   *
   * @param privateKey - the key you're signing with
   * @param hash - the message you're signing
   * @returns SignatureOutput
   */
  static sign(privateKey: Key, hash: string): SignatureOutput {
    const output = _sign(privateKey.buffer, hash)

    return {
      signature: new Signature(Buffer.from(output.signature)),
      publicNonce: new PublicNonce(Buffer.from(output.publicNonce)),
      challenge: new Challenge(Buffer.from(output.challenge)),
    }
  }

  /**
   * Sum two signatures.
   * Needed for a multisignature verification
   *
   * @param signatures
   * @returns Signature
   */
  static sumSigs(signatures: Signature[]): Signature {
    const mappedSignatures = signatures.map(signature => signature.buffer)
    const sum = _sumSigs(mappedSignatures)
    return new Signature(Buffer.from(sum))
  }

  /**
   * Off-chain signature verification
   *
   * @param signature - what we're verifying
   * @param hash - the message that should have been signed
   * @param publicNonce - the public version of the nonce used for the signature
   * @param publicKey - the public key of the private key used for the signature
   * @returns 
   */
  static verify(
    signature: Signature,
    hash: string,
    publicNonce: PublicNonce,
    publicKey: Key
  ): boolean {
    return _verify(signature.buffer, hash, publicNonce.buffer, publicKey.buffer)
  }
}

export default Schnorrkel