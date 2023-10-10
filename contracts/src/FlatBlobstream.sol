// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

struct FunctionRequest {
    bytes32 functionId;
    bytes32 inputHash;
    bytes32 outputHash;
    bytes32 contextHash;
    address callbackAddress;
    bytes4 callbackSelector;
    bool proofFulfilled;
    bool callbackFulfilled;
}

interface IFunctionGatewayEvents {
    event ProofRequested(
        uint256 indexed nonce,
        bytes32 indexed functionId,
        bytes32 requestId,
        bytes inputs,
        bytes context,
        uint256 gasLimit,
        uint256 feeAmount
    );
    event ProofFulfilled(bytes32 requestId, bytes32 outputHash, bytes proof);
    event ProofBatchFulfilled(
        bytes32[] requestIds,
        bytes aggregateProof,
        bytes32 inputsRoot,
        bytes32[] outputHashes,
        bytes32 outputsRoot,
        bytes32 verificationKeyRoot
    );
    event CallbackFulfilled(bytes32 requestId, bytes output, bytes context);
    event ScalarUpdated(uint256 scalar);
}

interface IFunctionGatewayErrors {
    error RequestNotFound(bytes32 requestId);
    error ContextMismatch(bytes32 contextHash, bytes context);
    error OutputMismatch(bytes32 outputHash, bytes context);
    error InputsRootMismatch(bytes32 inputsRoot, bytes32[] inputHashes);
    error OutputsRootMismatch(bytes32 outputsRoot, bytes32[] outputHashes);
    error VerificationKeysRootMismatch(bytes32 outputsRoot, bytes32[] outputHashes);
    error ProofNotFulfilled(bytes32 requestId);
    error ProofAlreadyFulfilled(bytes32 requestId);
    error InvalidProof(address verifier, bytes32 inputHash, bytes32 outputHash, bytes proof);
    error CallbackFailed(address callbackAddress, bytes4 callbackSelector);
    error CallbackAlreadyFulfilled(bytes32 requestId);
    error LengthMismatch(uint256 expected, uint256 actual);
    error InsufficientFeeAmount(uint256 expected, uint256 actual);
    error RefundFailed(address refundAccount, uint256 refundAmount);
}

interface IFunctionGateway is IFunctionGatewayEvents, IFunctionGatewayErrors {
    function requests(bytes32 requestId)
        external
        view
        returns (bytes32, bytes32, bytes32, bytes32, address, bytes4, bool, bool);

    function request(bytes32 functionId, bytes memory input, bytes4 callbackSelector, bytes memory context)
        external
        payable
        returns (bytes32);

    function request(
        bytes32 functionId,
        bytes memory input,
        bytes4 callbackSelector,
        bytes memory context,
        uint256 gasLimit,
        address refundAccount
    ) external payable returns (bytes32);

    function fulfill(bytes32 requestId, bytes32 outputHash, bytes memory proof) external;

    function fulfillBatch(
        bytes32[] memory requestIds,
        bytes memory aggregateProof,
        bytes32 inputsRoot,
        bytes32[] memory outputHashes,
        bytes32 outputsRoot,
        bytes32 verificationKeyRoot
    ) external;

    function callback(bytes32 requestId, bytes memory output, bytes memory context) external;

    function calculateFeeAmount() external view returns (uint256);

    function calculateFeeAmount(uint256 gasLimit) external view returns (uint256);
}

contract Blobstream {
    address public gateway;
    mapping(string => bytes32) public functionNameToId;

    mapping(uint64 => bytes32) public blockHeightToHeaderHash;

    mapping(bytes32 => bytes32) public dataCommitments;

    uint64 latestBlock;

    uint64 DATA_COMMITMENT_MAX = 1000;

    event FunctionId(string name, bytes32 id);

    event CombinedStepRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    event CombinedStepFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
    );

    event CombinedSkipRequested(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 requestId
    );

    event CombinedSkipFulfilled(
        uint64 indexed startBlock,
        uint64 indexed targetBlock,
        bytes32 targetHeader,
        bytes32 dataCommitment
    );

    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can call this function");
        _;
    }

    constructor(address _gateway) {
        gateway = _gateway;
    }

    function getFunctionId(string memory name) external view returns (bytes32) {
        return functionNameToId[name];
    }

    function getHeaderHash(uint64 height) external view returns (bytes32) {
        return blockHeightToHeaderHash[height];
    }

    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    function updateFunctionId(
        string memory name,
        bytes32 _functionId
    ) external {
        functionNameToId[name] = _functionId;
    }

    function setGenesisHeader(uint64 height, bytes32 header) external {
        blockHeightToHeaderHash[height] = header;
    }

    function requestCombinedSkip(uint64 _requestedBlock) external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        if (latestHeader == bytes32(0)) {
            revert("Trusted header not found");
        }
        bytes32 id = functionNameToId["combinedSkip"];
        if (id == bytes32(0)) {
            revert("Function ID for combined skip not found");
        }

        emit FunctionId("combinedSkip", id);

        require(_requestedBlock - latestBlock <= DATA_COMMITMENT_MAX); // TODO: change this constant (should match max number of blocks in a data commitment)
        require(_requestedBlock > latestBlock);
        bytes32 requestId = IFunctionGateway(gateway).request{value: msg.value}(
            id,
            abi.encodePacked(latestBlock, latestHeader, _requestedBlock),
            this.callbackCombinedSkip.selector,
            abi.encode(_requestedBlock)
        );
        emit CombinedSkipRequested(latestBlock, _requestedBlock, requestId);
    }

    function callbackCombinedSkip(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        uint64 requestedBlock = abi.decode(context, (uint64));
        (bytes32 newHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        blockHeightToHeaderHash[requestedBlock] = newHeader;

        dataCommitments[
            keccak256(abi.encode(latestBlock, requestedBlock))
        ] = dataCommitment;

        require(requestedBlock > latestBlock);
        latestBlock = requestedBlock;
        emit CombinedSkipFulfilled(
            latestBlock,
            requestedBlock,
            newHeader,
            dataCommitment
        );
    }

    // Needed in the rare case that skip cannot be used--when validator set changes by > 1/3
    function requestCombinedStep() external payable {
        bytes32 latestHeader = blockHeightToHeaderHash[latestBlock];
        // Note: Should never happen, deeply concerning if it does.
        if (latestHeader == bytes32(0)) {
            revert("Latest header not found");
        }
        bytes32 id = functionNameToId["combinedStep"];
        if (id == bytes32(0)) {
            revert("Function ID for combined step not found");
        }

        emit FunctionId("combinedStep", id);
        bytes32 requestId = IFunctionGateway(gateway).request{value: msg.value}(
            id,
            abi.encodePacked(latestBlock, latestHeader),
            this.callbackCombinedStep.selector,
            abi.encode(latestBlock)
        );
        emit CombinedStepRequested(latestBlock, latestBlock + 1, requestId);
    }

    function callbackCombinedStep(
        bytes memory requestResult,
        bytes memory context
    ) external onlyGateway {
        uint64 prevBlock = abi.decode(context, (uint64));
        (bytes32 nextHeader, bytes32 dataCommitment) = abi.decode(
            requestResult,
            (bytes32, bytes32)
        );

        uint64 nextBlock = prevBlock + 1;
        blockHeightToHeaderHash[nextBlock] = nextHeader;

        dataCommitments[
            keccak256(abi.encode(prevBlock, nextBlock))
        ] = dataCommitment;

        require(nextBlock > latestBlock);
        latestBlock = nextBlock;
        emit CombinedStepFulfilled(
            prevBlock,
            nextBlock,
            nextHeader,
            dataCommitment
        );
    }
}
