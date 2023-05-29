# Schnorr Signatures
A javaScript library for signing and verifying Schnorr Signatures.  
It can be used for single and multi signatures.  
Blockchain validation via ecrecover is also supported.  

# Typescript support
Since version 2.0.0, we're moving entirely to Typescript.

## Requirements:

* Node: >=16.0.0, <20.0.0
* npm (Node.js package manager) v9.x.x

## Installation

```
git clone https://github.com/borislav-itskov/schnorrkel.js
cd schnorrkel.js
npm i
```

### Testing
```
npm run test
```

## Usage

### Single Signatures
We refer to Single Signatures as ones that have a single signer.

Sign:
```
import Schnorrkel from 'schnorrkel'

const privateKey = randomBytes(32) // Buffer
const msg = 'test message'
const {signature, finalPublicNonce} = Schnorrkel.sign(privateKey, msg)
```

Offchain verification:
```
const publicKey: Uint8Array = ... (derived from the privateKey)
// signature and finalPublicNonce come from s
const result = Schnorrkel.verify(signature, msg, finalPublicNonce, publicKey)
```

Onchain verification:

First, you will need a contract that verifies schnorr. We have it in the repository and it is called `SchnorrAccountAbstraction`.  
But all in all, you need this onchain:
```
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
Let's send a request to this contract via hardhat:
```
const { ethers } = require("hardhat");

const SchnorrAccountAbstraction = await ethers.getContractFactory("SchnorrAccountAbstraction");
const contract = await SchnorrAccountAbstraction.deploy();
const privateKey: Uint8Array = '...'
const publicKey: Uint8Array = ... (derived from the privateKey)
const msg = 'just a test message';
const sig = schnorrkel.sign(msg, privateKey);

// wrap the result
const px = publicKey.slice(1, 33);
const parity = publicKey[0] - 2 + 27;
const abiCoder = new ethers.utils.AbiCoder();
const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
    px,
    sig.e,
    sig.s,
    parity
]);
const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
const result = await contract.isValidSignature(msgHash, sigData);
```

You can find reference to this in `tests/SingleSignTest.js` in this repository.

### Multisig

Schnorr multisignatures work on the basis n/n - all of the signers need to sign in order for the signature to be valid.  
Below are all the steps needed to craft a successful multisig.

#### Public nonces

Public nonces need to be exchanged between signers before they sign. Normally, the Signer should implement this library as define a `getPublicNonces` method that will call the library and return the nonces. For our test example, we're going to call the schnorrkel library directly:

```
const privateKey1: Uint8Array = '...'
const privateKey2: Uint8Array = '...'
const publicNonces1 = schnorrkel.generatePublicNonces(privateKey1);
const publicNonces2 = schnorrkel.generatePublicNonces(privateKey2);
```

Again, this isn't how the flow is supposed to work. A signer needs to implement the library and when `getPublicNonces` is called, the user should be ask whether he is okay to generate and give his public nonces.

#### sign

After we have them, here is how to sign:

```
const publicKey1: Uint8Array = '...'
const publicKey2: Uint8Array = '...'
const publicKeys = [publicKey1, publicKey2];
const combinedPublicKey = schnorrkel.getCombinedPublicKey(publicKeys)
const {s: sigOne, e, R} = schnorrkel.multiSigSign(privateKey1, msg, publicKeys, publicNonces)
const {s: sigTwo} = schnorrkel.multiSigSign(privateKey2, msg, publicKeys, publicNonces)
const sSummed = schnorrkel.sumSigs([sigOne, sigTwo]);
```

#### verify onchain

```
const px = combinedPublicKey.slice(1,33);
const parity = combinedPublicKey[0] - 2 + 27;
const abiCoder = new ethers.utils.AbiCoder();
const sigData = abiCoder.encode([ "bytes32", "bytes32", "bytes32", "uint8" ], [
    px,
    e,
    sSummed,
    parity
]);
const msgHash = ethers.utils.solidityKeccak256(['string'], [msg]);
const result = await contract.isValidSignature(msgHash, sigData);
```

#### verify offchain

```
const result = schnorrkel.verify(sSummed, msg, R, combinedPublicKey);
```

You can find reference to this in `tests/MultiSigTest.js` in this repository.

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

* calculate e' = h(address(Q) || m)
* check e' == e to verify the signature.
