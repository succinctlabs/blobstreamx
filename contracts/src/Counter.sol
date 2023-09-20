// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface IGateway {
    function request() {}
}

contract ZKTendermint {
    address public gateway;
    mapping(string => bytes32) public functionNameToId;
    bytes32 public functionId;

    mapping(uint64 => bytes32) public blockHeightToHeaderHash;
    uint64 head;

    constructor(address _gateway) {
        gateway = _gateway;
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

    function requestHeaderSkip(
        uint64 _trustedBlock,
        uint64 _requestedBlock
    ) external {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert("Trusted header not found");
        }
        bytes32 id = functionNameToId["skip"];
        if (id == bytes32(0)) {
            revert("Function ID for skip not found");
        }
        require(_requestedBlock > _trustedBlock);
        require(_requestedBlock - _trustedBlock <= 10000); // TODO: change this constant
        require(_requestedBlock > head); // TODO: do we need this?
        bytes memory result = IGateway(gateway).request(
            id,
            abi.encodePacked(trustedHeader, _trustedBlock, _requestedBlock),
            this.callbackHeaderSkip,
            abi.encode(_trustedBlock, _requestedBlock)
        );
    }

    function callbackHeaderSkip(
        bytes memory requestResult,
        bytes memory context
    ) external {
        (uint64 trustedBlock, uint64 requestedBlock) = abi.decode(
            context,
            (uint64, uint64)
        );
        bytes32 newHeader = abi.decode(requestResult, (bytes32));
        blockHeightToHeaderHash[requestedBlock] = newHeader;
        require(requestedBlock > head);
        head = requestedBlock;
    }

    // Needed in the rare case that skip cannot be used--when validator set changes by > 1/3
    function requestHeaderStep(uint64 _prevBlock) public {
        bytes32 prevHeader = blockHeightToHeaderHash[_prevBlock];
        if (prevHeader == bytes32(0)) {
            revert("Prev header not found");
        }
        bytes32 id = functionNameToId["step"];
        if (id == bytes32(0)) {
            revert("Function ID for step not found");
        }
        require(_prevBlock + 1 > head); // TODO: do we need this?
        bytes memory result = IGateway(gateway).request(
            id,
            abi.encodePacked(prevHeader, _prevBlock),
            this.callbackHeaderStep,
            abi.encode(_prevBlock)
        );
    }

    function callbackHeaderStep(
        bytes memory requestResult,
        bytes memory context
    ) external {
        uint64 prevBlock = abi.decode(context, (uint64));
        bytes32 nextHeader = abi.decode(requestResult, (bytes32));
        uint64 nextBlock = prevBlock + 1;
        blockHeightToHeaderHash[nextBlock] = nextHeader;
        require(nextBlock > head);
        head = nextBlock;
    }
}

// contract QGB {
//     mapping(uint256 => bytes32) public dataRoot;

//     function verifyDataRoot(
//         uint256 _startBlock,
//         uint256 _endBlock
//     ) public pure returns (bool) {
//         bytes32 startHeader = ZKTendermint().header(_startBlock);
//         bytes32 endHeader = ZKTendermint().header(_endBlock);
//         bytes memory dataRootTuple = IGateway(gateway).zkCall(
//             functionId, // dataRoot
//             abi.encodePacked(startHeader, endHeader)
//         );
//         bytes32 dataRoot = abi.decode(dataRootTuple, (bytes32));
//         dataRoot[abi.encodePacked(_startBlock, _endBlock)] = dataRoot;
//     }

//     function verifyMerkleProof(
//         uint256 startBlock,
//         uint256 endBlock,
//         bytes32[] memory proof
//     ) {
//         // TODO: existing proof verification code
//     }
// }
