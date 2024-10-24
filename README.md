# Schnorr Signatures

A javaScript library for signing and verifying Schnorr Signatures.  
It can be used for single and multi signatures.  
Blockchain validation via ecrecover is also supported.

# Typescript support

Since version 2.0.0, we're moving entirely to Typescript.

## Version 2.0 Breaking changes

- `sign()` and `multiSigSign()` return an instance of `SignatureOutput`. Each element in it has a buffer property
  - instead of `e` we return `challenge` for the Schnorr Challenge. To accces its value, use `challenge.buffer`
  - instead of `s` we return `signature` for the Schnorr Signature. To accces its value, use `signature.buffer`
  - instead of `R` we return `publicNonce` for the nonce. To accces its value, use `publicNonce.buffer`
- `getCombinedPublicKey()` returns a `Key` class. To get the actual key, use `key.buffer`
- a lot of method become static as they don't keep any state:
  - `verify`
  - `sign`
  - `sumSigs`
  - `getCombinedPublicKey`
  - `getCombinedAddress`

## Version 3.0 Breaking changes

- `finalPublicNonce`, `FinalPublicNonce` is replaced everywhere with `publicNonce`, `PublicNonce`. The old name just didn't make sense.
- `sign()` is the former `signHash()`. A sign function that accepts a plain-text message as an argument no longer exists.
- `multiSigSign()` is the former `multiSigSignHash()`. A sign function that accepts a plain-text message as an argument no longer exists.
- `verify()` is the former `verifyHash()`. A verification function that accepts a plain-text message as an argument no longer exists.

In version 2, we had plenty of ways to sign a message. This broad a lot of confusion as to what function was the correct one to use in various situations. This lead us to believe that making things simpler and forcing a hash to be passed to the methods is the way forward.

## Requirements:

- Node: >=16.0.0, <20.0.0
- npm (Node.js package manager) v9.x.x

## Installation

```
git clone https://github.com/borislav-itskov/schnorrkel.js
cd schnorrkel.js
npm i
```

## Testing

```
npm run test
```

## Usage

### Single Signatures

We refer to Single Signatures as ones that have a single signer.

Sign:

```js
import { SchnorrSigner } from "@borislav.itskov/schnorrkel.js";
import { hexlify, randomBytes, hashMessage } from "ethers/lib/utils";

const privateKey = hexlify(randomBytes(32));
const signer = new SchnorrSigner(pk1);
const msg = "test message";
const commitment = hashMessage(msg);
const signature = signer.sign(commitment);
```

Offchain verification:
We take the `signature` and `hash` from the example above and do:

```js
const result = signer.verify(hash, signature);
```

Onchain verification:

First, you will need a contract that verifies schnorr. We have it in the repository and it is called `SchnorrAccountAbstraction`.  
But all in all, you need this onchain:

```js
function verifySchnorr(bytes32 hash, bytes memory sig) internal pure returns (bool) {
    // px := public key x-coord
    // e := schnorr signature challenge
    // s := schnorr signature
    // parity := public key y-coord parity (27 or 28)
    (bytes32 px, bytes32 e, bytes32 s, uint8 parity) = abi.decode(sig, (bytes32, bytes32, bytes32, uint8));
    // ecrecover = (m, v, r, s);
    bytes32 sp = bytes32(Q - mulmod(uint256(s), uint256(px), Q));
    bytes32 ep = bytes32(Q - mulmod(uint256(e), uint256(px), Q));

    require(sp != Q);
    // the ecrecover precompile implementation checks that the `r` and `s`
    // inputs are non-zero (in this case, `px` and `ep`), thus we don't need to
    // check if they're zero.
    address R = ecrecover(sp, parity, px, ep);
    require(R != address(0), "ecrecover failed");
    return e == keccak256(abi.encodePacked(R, uint8(parity), px, hash));
}
```

We explain how ecrecover works and why it is needed later [in this document](#ecrecover).  
Let's send a request to the local hardhat node. First run in the terminal:  
npx hardhat node  
Afterwards, here is part of the code:

```js
import { SchnorrSigner } from "@borislav.itskov/schnorrkel.js";
import { hexlify, randomBytes, hashMessage } from "ethers/lib/utils";
import { ContractFactory } from "ethers";

const privateKey = hexlify(randomBytes(32));
const signer = new SchnorrSigner(privateKey);
const factory = new ContractFactory(
  SchnorrAccountAbstraction.abi,
  SchnorrAccountAbstraction.bytecode,
  wallet
);
const contract: any = await factory.deploy([signer.getSchnorrAddress()]);
const msg = "just a test message";
const commitment = hashMessage(msg);
const sig = signer.sign(commitment);
const result = await contract.isValidSignature(
  commitment,
  signer.getEcrecoverSignature(sig)
);
```

You can see the full implementation in `tests/schnorrkel/onchainSingleSign.test.ts` in this repository.

### Multisig

Schnorr multisignatures work on the basis n/n - all of the signers need to sign in order for the signature to be valid.  
Below are all the steps needed to craft a successful multisig.

### MultisigProvider

To make multisig easier, a `SchnorrMultisigProvider` class was created. It expects all `SchnorrProvider` objects that participate in the multisig. The `SchnorrProvider` can be passed by itself or one could use the `SchnorrSigner`. The meaninful point is that you don't need possession of the private keys to use the `SchnorrMultisigProvider`. It's goal is to provider helper functions for fetching the correct on-chain schnorr address, the combined public key of all the signers and provide a easy way to fetch the expected on-chain structure for validation

```js
import {
  SchnorrSigner,
  SchnorrMultisigProvider,
} from "@borislav.itskov/schnorrkel.js";

const signerOne = new SchnorrSigner(pk1);
const signerTwo = new SchnorrSigner(pk2);
const multisigProvider = new SchnorrMultisigProvider([signerOne, signerTwo]);
```

#### Public nonces

Public nonces need to be exchanged between signers before they sign. You can do this in two ways.  
Using the multisigProvider:

```js
const publicNonces = multisigProvider.getPublicNonces();
```

Or manually by calling each signer individially:

```js
const publicNonces = [signerOne.getPublicNonces(), signerOne.getPublicNonces()];
```

Nonces need to be exchanged before signing can begin. Also, `getPublicNonces` should not be called again before all signers complete their signing process. Or at least one should be careful not to mixes the public nonces with newly generated ones. In the case of mixed nonces, signing will not work.

#### sign

Here is an example of a signing process. Public keys and public nonce can be retriever either manually by calling the signer or directly by calling the multisigProvider.

```js
import { solidityKeccak256 } from "ethers/lib/utils";

const msg = "just a test message";
const msgHash = solidityKeccak256(["string"], [msg]);
const publicKeys = multisigProvider.getPublicKeys();
const publicNonces = multisigProvider.getPublicNonces();
const signature = signerOne.sign(msgHash, publicKeys, publicNonces);
const signatureTwo = signerTwo.sign(msgHash, publicKeys, publicNonces);
```

#### verify onchain

Generation of the encoded data for the on-chain verification is somewhat complex and therefore, it's hidden away in the `multisigProvider`.  
Here's an example of how to perform an on-chain verification using the provider:

```js
const ecRecoverSchnorr = multisigProvider.getEcrecoverSignature([
  signature,
  signatureTwo,
]);
const result = await contract.isValidSignature(msgHash, ecRecoverSchnorr);
```

Here's also an example of how you can do it without the multisigProvider:

```js
import Schnorrkel from "@borislav.itskov/schnorrkel.js";
import { defaultAbiCoder } from "ethers/lib/utils";

const publicKeys = [signerOne.publicKey, signerTwo.publicKey];
const publicKey = arrayify(Schnorrkel.getCombinedPublicKey(publicKeys).buffer);
const sigOutputs = [signature, signatureTwo];
const sSummed = Schnorrkel.sumSigs(
  sigOutputs.map((output) => output.signature)
);
const challenge = sigOutputs[0].challenge;
const px = publicKey.slice(1, 33);
const parity = publicKey[0] - 2 + 27;
const ecRecoverSchnorr = defaultAbiCoder.encode(
  ["bytes32", "bytes32", "bytes32", "uint8"],
  [px, challenge.buffer, sSummed.buffer, parity]
);
const result = await contract.isValidSignature(msgHash, ecRecoverSchnorr);
```

#### verify offchain

With the multisig provider:

```js
const result = multisigProvider.verify(msgHash, [signature, signatureTwo]);
```

Without it:

```js
import Schnorrkel from "@borislav.itskov/schnorrkel.js";

const publicKeys = [signerOne.publicKey, signerTwo.publicKey];
const sigOutputs = [signature, signatureTwo];
const sSummed = Schnorrkel.sumSigs(
  sigOutputs.map((output) => output.signature)
);

return _verify(
  sSummed.buffer,
  msgHash,
  sigOutputs[0].publicNonce.buffer,
  Schnorrkel.getCombinedPublicKey(publicKeys).buffer
);
```

You can find reference to this in `tests/schnorrkel/onchainMultiSign.test.ts` in this repository.

## ecrecover

For the schnorr on-chain verification, we were inspired by the work of [noot](https://github.com/noot). Without his work, it would've required a lot more time for RnD to reach this point. You can take a look at his repository [here](https://github.com/noot/schnorr-verify)

We utilize Ethereum ecrecover to verify the signature. This is how it works:  
Ethereum ecrecover returns an address (hash of public key) given an ECDSA signature.
Given message m and ECDSA signature (v, r, s) where v denotes the parity of the y-coordinate for the point where x-coordinate r

```
ecrecover(m, v, r, s):
R = point derived from r and v
a = -G*m
b = R*s
Qr = a + b
Q = Qr * (1/r)
Q = (1/r) * (R*s - G*m) //recovered pubkey
```

Ethereum’s ecrecover returns the last 20 bytes of the keccak256 hash of the 64-byte public key.
Given signature (R, s), message m and public key P we can feed values into ecrecover such that the returned address can be used in a comparison to the challenge.

```
calculate e = H(address(R) || m) and P_x = x-coordinate of P
```

pass:

```
m = -s*P_x
v = parity of P
r = x-coordinate of P
s = -e*P_x
```

then:

```
ecrecover(m=-s*P_x, v=0/1, r=P_x, s=-e*P_x):
P = point derived from r and v (public key)
a = -G*(-s*P_x) = G*s*P_x
b = P*(-m*P_x) = -P*e*P_x
Q = (1/P_x) (a+b)
Q = (1/P_x)(G*s*P_x - P*e*P_x)
Q = G*s - P*e  // same as schnorr verify above
```

the returned value is address(Q).

- calculate e' = h(address(Q) || m)
- check e' == e to verify the signature.
