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
