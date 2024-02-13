# Blobstream X Contracts

This folder contains the smart contracts for Blobstream X.

## Deploy new Blobstream X contract

Fill out the following fields in `.env` in `contracts` folder:

- `PRIVATE_KEY` - Private key of the account that will deploy the contract
- `RPC_URL` - URL of the Ethereum RPC node
- `ETHERSCAN_API_KEY` - API key for Etherscan
- `CREATE2_SALT` - Salt for CREATE2 deployment (determinstic deployment)
- `GATEWAY_ADDRESS` - Address of the gateway contract
- `GENESIS_HEIGHT` - Height of the block at which the contract will be deployed
- `GENESIS_HEADER` - Header of the block at which the contract will be deployed

Then run the following command:

```bash
source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

## Upgrade existing Blobstream X contract

In addition to the fields in `.env` for deployment, fill out the following fields in `.env` in `contracts` folder:

- `CONTRACT_ADDRESS` - Address of the contract to upgrade
- `UPGRADE` - Set to `true` to upgrade the contract
- `UPDATE_GENESIS_STATE` - Updates the genesis state of the contract using `GENESIS_HEIGHT` and `GENESIS_HEADER`.
- `UPDATE_GATEWAY` - Updates the gateway address of the contract using `GATEWAY_ADDRESS`.
- `UPDATE_FUNCTION_IDS` - Updates the function IDs of the contract using `NEXT_HEADER_FUNCTION_ID` and `HEADER_RANGE_FUNCTION_ID`.
  Then run the following command:

```bash
source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```
