# zkqgb
Implementation of zero-knowledge proof circuits for Tendermint and QGB to verify Celestia's consensus protocol and data commitments.

## Circuit Release
The circuit release is available on the Succinct platform [here](https://alpha.succinct.xyz/succinctlabs/zkqgb/releases).

## QGB
### Testnet
Goerli Contract: [0x7eE75Da23875893FFB4f6F26458629C244e61e49](https://goerli.etherscan.io/address/0x7eE75Da23875893FFB4f6F26458629C244e61e49)

Deployed for a maximum data commitment size of 256 blocks.

### Performance
256 blocks: 251s (~4 minutes)
1024 blocks: 1121s (~18 minutes)

## Tendermint Light Client
### Testnet
Goerli Contract: [0xB1cdc97E3C9fC29a30da31e49B4e2304b011d631](https://goerli.etherscan.io/address/0xB1cdc97E3C9fC29a30da31e49B4e2304b011d631)

Deployed for a maximum validator set size of 128 validators.

### Performance
Step with 128 validators: 927s (~15 minutes)
Skip with 128 validators: 927s (~15 minutes) 