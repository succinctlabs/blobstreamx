// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./ZKTendermintLightClient.sol";

contract QGB {
    address public gateway;
    mapping(string => bytes32) public functionNameToId;
    bytes32 public functionId;

    mapping(bytes32 => bytes32) public dataCommitments;

    uint64 latestBlock;
    uint64 DATA_COMMITMENT_MAX = 1000;

    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can call this function");
        _;
    }

    function requestDataCommitment(uint64 targetBlock) external {
        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert("Trusted header not found");
        }
        bytes32 targetHeader = blockHeightToHeaderHash[targetBlock];
        if (targetHeader == bytes32(0)) {
            revert("Target header not found");
        }
        bytes32 id = functionNameToId["data_commitment"];
        if (id == bytes32(0)) {
            revert("Function ID for data_commitment not found");
        }
        require(targetBlock > latestBlock);
        require(targetBlock - latestBlock <= DATA_COMMITMENT_MAX); // TODO: change this constant
        bytes32 requestId = IFunctionGateway(gateway).request(
            id,
            abi.encodePacked(
                latestBlock,
                trustedHeader,
                targetBlock,
                targetHeader
            ),
            this.callbackCommitment.selector,
            abi.encode(startBlock, targetBlock)
        );
        emit DataCommitmentRequested(_trustedBlock, _requestedBlock, requestId);
    }

    function callbackCommitment(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        (uint64 startBlock, uint64 targetBlock) = abi.decode(
            context,
            (uint64, uint64)
        );
        bytes32 dataCommitment = abi.decode(requestResult, (bytes32));
        dataCommitments[
            keccak256(abi.encode(startBlock, targetBlock))
        ] = dataCommitment;
        latestBlock = targetBlock;
        emit DataCommitmentFulfilled(startBlock, targetBlock, dataCommitment);
    }

    function verifyMerkleProof(
        uint256 startBlock,
        uint256 endBlock,
        bytes32[] memory proof
    ) {
        // TODO: existing proof verification code
    }
}
