# Blobstream X
Implementation of zero-knowledge proof circuits for [Blobstream](https://docs.celestia.org/nodes/blobstream-intro/), Celestia's data availability solution for Ethereum.

## Overview
Blobstream X's core contract is `BlobstreamX`, which stores commitments to ranges of data roots from Celestia blocks. Users can query the for the validity of a data root of a specific block height via `verifyAttestation`, which proves that the data root is a leaf in the Merkle tree for the block range the specific block height is in.

### headerRange
`headerRange` is used to generate the data root of a block range. The data root is the root of a Merkle tree of the data roots of all the blocks in the block range. 

To prove the last header of a block range, `headerRange` uses `skip` as a sub-circuit. After proving the last header, the `headerRange` circuit proves the chain of headers from the start header to the last header. From a valid chain of headers, the `headerRange` circuit can generate the commitment of the block range with the data root of each block in the block range.

### nextHeader
`nextHeader` is used to generate the commitment to the data root of the current block.

This is rarely used, as `nextHeader` will only be invoked when the validator set changes by more than 2/3 in a single block.


## Deployment
The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/succinctlabs/zkqgb/releases).

Blobstream X is currently deployed for Celestia's Mocha-4 testnet on Goerli [here](https://goerli.etherscan.io/address/0x67ea962864cdad3f2202118dc6f65ff510f7bb4d).

## Integrate
Deploy a `BlobstreamX` contract.
```
forge create --rpc-url $RPC_URL --private-key $PRIVATE_KEY --constructor-args 0x6e4f1e9ea315ebfd69d18c2db974eef6105fb803 --etherscan-api-key $ETHERSCAN_API_KEY --verify BlobstreamX
```

Initialize `BlobstreamX` contract with genesis parameters.
```
forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

Update the function ID's on the `BlobstreamX` contract.
```
forge script script/FunctionId.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

Update .env file with contract address and chain id.

Run `BlobstreamX` script to update the light client continuously.
```
cargo run --bin blobstreamx --release
```
