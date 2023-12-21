# Blobstream X
![Blobstream X](https://pbs.twimg.com/media/F85boT-bYAAF1hM?format=jpg&name=4096x4096)

Implementation of zero-knowledge proof circuits for [Blobstream](https://docs.celestia.org/developers/blobstream), Celestia's data availability solution for Ethereum.

## Overview
Blobstream X's core contract is `BlobstreamX`, which stores commitments to ranges of data roots from Celestia blocks. Users can query for the validity of a data root of a specific block height via `verifyAttestation`, which proves that the data root is a leaf in the Merkle tree for the block range the specific block height is in.

### headerRange
`headerRange` is used to generate the data root of a block range. The data root is the root of a Merkle tree of the data roots of all the blocks in the block range. 

To prove the last header of a block range, `headerRange` uses `skip` as a sub-circuit. After proving the last header, the `headerRange` circuit proves the chain of headers from the start header to the last header. From a valid chain of headers, the `headerRange` circuit can generate the commitment of the block range with the data root of each block in the block range.

### nextHeader
`nextHeader` is used to generate the commitment to the data root of the current block.

This is rarely used, as `nextHeader` will only be invoked when the validator set changes by more than 2/3 in a single block.


## Deployment
The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/celestia/blobstreamx/releases).

Blobstream X is currently deployed for Celestia Mainnet on Goerli [here](https://goerli.etherscan.io/address/0x046120E6c6C48C05627FB369756F5f44858950a5#events).

## Integrate
Get the genesis parameters for the `BlobstreamX` contract with a specific Celestia block (with no input defaults to block 1).
```
cargo run --bin genesis -- --block 100
```

Add .env variables to `contracts/.env`, following `contracts/.env.example`.

Initialize `BlobstreamX` contract with genesis parameters.

In `contracts/`, run
```
forge install

source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

Add env variables to `.env`, following `.env.example`.

Run `BlobstreamX` script to update the light client continuously.

In `/`, run
```
cargo run --bin blobstreamx --release
```
