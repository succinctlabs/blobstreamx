# Blobstream X
Implementation of zero-knowledge proof circuits for [Blobstream](https://docs.celestia.org/nodes/blobstream-intro/), Celestia's data availability solution for Ethereum.

## Overview (wip)
Blobstream X's core contract is `ZKBlobstream`, which stores commitments to ranges of data roots from Celestia blocks. Users can query the for the validity of a data root of a specific block height via `verifyAttestation`, which proves that the data root is a leaf in the Merkle tree for the block range the specific block height is in.

### headerRange (wip)
`headerRange` is used to generate the data root of a block range. The data root is the root of a Merkle tree of the data roots of all the blocks in the block range. 

To prove the last header of a block range, `headerRange` uses `skip` as a sub-circuit. After proving the last header, the `headerRange` circuit proves the chain of headers from the start header to the last header. From a valid chain of headers, the `headerRange` circuit can generate the commitment of the block range with the data root of each block in the block range.

### nextHeader (wip)
`nextHeader` is used to generate the commitment to the data root of the current block.

This is rarely used, as `nextHeader` will only be invoked when the validator set changes by more than 2/3 in a single block.


## Deployment
The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/succinctlabs/zkqgb/releases).

Blobstream X is currently deployed for Celestia's Mocha-4 testnet on Goerli [here](https://goerli.etherscan.io/address/0x67ea962864cdad3f2202118dc6f65ff510f7bb4d).
