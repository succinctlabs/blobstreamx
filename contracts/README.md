# Blobstream X Contracts

## Deploy new Blobstream X contract

Fill out the following fields in `.env` in `contracts` folder:

- `DEPLOY` - Set to `true` to deploy the contract
- `PRIVATE_KEY` - Private key of the account that will deploy the contract
- `RPC_URL` - URL of the Ethereum RPC node
- `ETHERSCAN_API_KEY` - API key for Etherscan
- `CREATE2_SALT` - Salt for CREATE2 deployment (determinstic deployment)
- `GUARDIAN_ADDRESS` - Address of the guardian (multi-sig/Gnosis Safe).
- `GATEWAY_ADDRESS` - Address of the gateway contract
- `GENESIS_HEIGHT` - Height of the block at which the contract will be deployed
- `GENESIS_HEADER` - Header of the block at which the contract will be deployed
- `NEXT_HEADER_FUNCTION_ID` - Function ID for `nextHeader` function
- `HEADER_RANGE_FUNCTION_ID` - Function ID for `headerRange` function

Then run the following command:

```bash
source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```

## Upgrade existing Blobstream X contract

In addition to the fields in `.env` for deployment, fill out the following fields in `.env` in `contracts` folder:

- `CONTRACT_ADDRESS` - Address of the contract to upgrade
- `UPGRADE` - Set to `true` to upgrade the contract
- `UPDATE_GENESIS_STATE` - Set to true to update the genesis state of the contract using `GENESIS_HEIGHT` and `GENESIS_HEADER`.
- `UPDATE_GATEWAY` - Set to true to update the gateway address of the contract using `GATEWAY_ADDRESS`.
- `UPDATE_FUNCTION_IDS` - Set to true to update the function IDs of the contract using `NEXT_HEADER_FUNCTION_ID` and `HEADER_RANGE_FUNCTION_ID`.
  Then run the following command:

```bash
source .env

forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --verify --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY
```
