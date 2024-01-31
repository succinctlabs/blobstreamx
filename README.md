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

## Current Deployment

The circuits are currently available on Succinct X [here](https://alpha.succinct.xyz/celestia/blobstreamx/releases).

Blobstream X is currently deployed for Celestia Mainnet on Sepolia [here](https://sepolia.etherscan.io/address/0x48B257EC1610d04191cC2c528d0c940AdbE1E439#events).

## Run Blobstream X Operator

### Operator with Hosted Proving

Add env variables to `.env`, following the `.env.example`. You do not need to fill out the local configuration, unless you're planning on doing local proving.

Run `BlobstreamX` script to request updates to the specified light client continuously. For the cadence of requesting updates, update `LOOP_DELAY_MINUTES`.

In `/`, run

```
cargo run --bin blobstreamx --release
```

### Local Proving & Relaying

To enable local proving & local relaying of proofs with the Blobstream X operator, download the proving binaries by following the instructions [here](https://hackmd.io/Q6CsiGOjTrCjD7UCAgiDBA#Download-artifacts).

Then, simply add the following to your `.env`:

```
LOCAL_PROVE_MODE=true
LOCAL_RELAY_MODE=true

# Add the path to each binary (ex. PROVE_BINARY_0x6d...=blobstream-artifacts/header_range)
PROVE_BINARY_0xFILL_IN_NEXT_HEADER_FUNCTION_ID=
PROVE_BINARY_0xFILL_IN_HEADER_RANGE_FUNCTION_ID=
WRAPPER_BINARY=
```

#### Relay an Existing Proof

Add env variables to `.env`, following the `.env.example`.

If you want to relay an existing proof in `/proofs`, run the following command:

```
cargo run --bin local_relay --release -- --request-id {REQUEST_ID}
```

## Deploy Blobstream X Contract

Get the genesis parameters for a `BlobstreamX` contract from a specific Celestia block.

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
