// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.22;

import "forge-std/Script.sol";
import {BlobstreamX} from "../src/BlobstreamX.sol";

// forge script script/BlobstreamX.s.sol --verifier etherscan --private-key
// forge verify-contract <address> BlobstreamX --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        address gateway = address(0x6e4f1e9eA315EBFd69d18C2DB974EEf6105FB803);

        // Use the below to interact with an already deployed Blobstream
        BlobstreamX blobstream = BlobstreamX(
            0x046120E6c6C48C05627FB369756F5f44858950a5
        );

        // Update gateway to new address.
        blobstream.updateGateway(gateway);

        uint64 height = 1;
        bytes32 header = hex"6be39efd10ba412a9db5288488303f5dd32cf386707a5bef33617f4c43301872";
        blobstream.setGenesisHeader(height, header);
    }
}
