# Tendermint X
Implementation of zero-knowledge proof circuits for [Tendermint](https://tendermint.com/).

## Overview
Tendermint X's core contract is `ZKTendermint`, which stores the headers of Tendermint blocks. Users can query a `ZKTendermint` contract for the header of a specific block height, or for the latest header.

There are two entrypoints to a `ZKTendermint` contract, `step` and `skip`.

### skip
`skip` is used to jump from the current header to a non-consecutive header. 

For example, let's say block N has already been proven in the light client, and we want to prove block N+10. If validators from block N represent more than 1/3 of the voting power in block N+10, then we can skip from block N to block N+10, as long as 1) the validators from the trusted block have signed the new block, and 2) the new block is valid.

The methodology for doing so is described in the section 2.3 of [A Tendermint Light Client](https://arxiv.org/pdf/2010.07031.pdf).

### step
`step` is used to sequentially verify the next header after the current header.

This is rarely used, as `step` will only be invoked when the validator set changes by more than 2/3 in a single block.

## Deployment
The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/succinctlabs/zkqgb/releases).

There are currently ZK Tendermint light clients tracking the following networks on Goerli:
- [Celestia Mocha-4 Testnet](https://goerli.etherscan.io/address/0x67ea962864cdad3f2202118dc6f65ff510f7bb4d)
- [Osmosis Mainnet]


# Blobstream X
Implementation of zero-knowledge proof circuits for [Blobstream](https://docs.celestia.org/nodes/blobstream-intro/), Celestia's data availability solution for Ethereum.

## Overview
Blobstream X's core contract is `ZKBlobstream`, which stores commitments to ranges of data roots from Celestia blocks. Users can query the for the validity of a data root of a specific block height via `verifyMerkleProof`, which proves that the data root is a leaf in the Merkle tree for the block range the specific block height is in.

### headerRange
`headerRange` is used to generate the data root of a block range. The data root is the root of a Merkle tree of the data roots of all the blocks in the block range. 

To prove the last header of a block range, `headerRange` uses `skip` as a sub-circuit. After proving the last header, the `headerRange` circuit proves the chain of headers from the start header to the last header. From a valid chain of headers, the `headerRange` circuit can generate the commitment of the block range with the data root of each block in the block range.

### nextHeader
`nextHeader` is used to generate the commitment to the data root of the current block.

This is rarely used, as `nextHeader` will only be invoked when the validator set changes by more than 2/3 in a single block.


## Deployment
The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/succinctlabs/zkqgb/releases).

Blobstream X is currently deployed for Celestia's Mocha-4 testnet on Goerli [here](https://goerli.etherscan.io/address/0x67ea962864cdad3f2202118dc6f65ff510f7bb4d).
