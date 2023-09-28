// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./IZKTendermintLightClient.sol";
import "@succinctx/interfaces/IFunctionGateway.sol";
import "@qgb/DataRootTuple.sol";
import "@qgb/lib/tree/binary/BinaryMerkleTree.sol";

contract QGB {
    address public gateway;
    IZKTendermintLightClient public tendermintLightClient;

    bytes32 public functionId;

    mapping(bytes32 => bytes32) public dataCommitments;

    uint64 public latestBlock;
    uint64 DATA_COMMITMENT_MAX = 1000;

    event DataCommitmentRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    event DataCommitmentFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 dataCommitment
    );

    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can call this function");
        _;
    }

    constructor(address _gateway, address _tendermintLightClient) {
        gateway = _gateway;
        tendermintLightClient = IZKTendermintLightClient(
            _tendermintLightClient
        );
    }

    function getGateway() external view returns (address) {
        return gateway;
    }

    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    function setLatestBlock(uint64 _latestBlock) external {
        latestBlock = _latestBlock;
    }

    function updateTendermintLightClient(
        address _tendermintLightClient
    ) external {
        tendermintLightClient = IZKTendermintLightClient(
            _tendermintLightClient
        );
    }

    function updateFunctionId(bytes32 _functionId) external {
        functionId = _functionId;
    }

    function requestDataCommitment(uint64 targetBlock) external payable {
        bytes32 latestHeader = tendermintLightClient.getHeaderHash(latestBlock);
        if (latestHeader == bytes32(0)) {
            revert("Trusted header not found");
        }
        bytes32 targetHeader = tendermintLightClient.getHeaderHash(targetBlock);
        if (targetHeader == bytes32(0)) {
            revert("Target header not found");
        }
        if (functionId == bytes32(0)) {
            revert("Function ID for data_commitment not found");
        }
        require(targetBlock > latestBlock);
        require(targetBlock - latestBlock <= DATA_COMMITMENT_MAX); // TODO: change this constant
        bytes32 requestId = IFunctionGateway(gateway).request{value: msg.value}(
            functionId,
            abi.encodePacked(
                latestBlock,
                latestHeader,
                targetBlock,
                targetHeader
            ),
            this.callbackCommitment.selector,
            abi.encode(latestBlock, targetBlock)
        );
        emit DataCommitmentRequested(latestBlock, targetBlock, requestId);
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
        DataRootTuple memory _tuple,
        BinaryMerkleProof memory _proof
    ) external view returns (bool) {
        // Tuple must have been committed before.
        if (endBlock > latestBlock) {
            return false;
        }

        // Load the tuple root at the given index from storage.
        bytes32 root = dataCommitments[
            keccak256(abi.encode(startBlock, endBlock))
        ];

        // Verify the proof.
        bool isProofValid = BinaryMerkleTree.verify(
            root,
            _proof,
            abi.encode(_tuple)
        );

        return isProofValid;
    }
}
