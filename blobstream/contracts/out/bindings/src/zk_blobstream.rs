pub use zk_blobstream::*;
/// This module was auto-generated with ethers-rs Abigen.
/// More information at: <https://github.com/gakonst/ethers-rs>
#[allow(
    clippy::enum_variant_names,
    clippy::too_many_arguments,
    clippy::upper_case_acronyms,
    clippy::type_complexity,
    dead_code,
    non_camel_case_types,
)]
pub mod zk_blobstream {
    pub use super::super::shared_types::*;
    #[allow(deprecated)]
    fn __abi() -> ::ethers::core::abi::Abi {
        ::ethers::core::abi::ethabi::Contract {
            constructor: ::core::option::Option::Some(::ethers::core::abi::ethabi::Constructor {
                inputs: ::std::vec![
                    ::ethers::core::abi::ethabi::Param {
                        name: ::std::borrow::ToOwned::to_owned("_gateway"),
                        kind: ::ethers::core::abi::ethabi::ParamType::Address,
                        internal_type: ::core::option::Option::Some(
                            ::std::borrow::ToOwned::to_owned("address"),
                        ),
                    },
                ],
            }),
            functions: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("DATA_COMMITMENT_MAX"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "DATA_COMMITMENT_MAX",
                            ),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("blockHeightToHeaderHash"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "blockHeightToHeaderHash",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("callbackCombinedSkip"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "callbackCombinedSkip",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("requestResult"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("context"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("callbackCombinedStep"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "callbackCombinedStep",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("requestResult"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("context"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bytes,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("dataCommitments"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("dataCommitments"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("functionNameToId"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("functionNameToId"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::String,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("string"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("gateway"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("gateway"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Address,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("address"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("getDataCommitment"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("getDataCommitment"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("startBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("endBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("getFunctionId"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("getFunctionId"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("name"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::String,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("string"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("getHeaderHash"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("getHeaderHash"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("height"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("latestBlock"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("latestBlock"),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("requestCombinedSkip"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "requestCombinedSkip",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("_requestedBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::Payable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("requestCombinedStep"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned(
                                "requestCombinedStep",
                            ),
                            inputs: ::std::vec![],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::Payable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("setGenesisHeader"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("setGenesisHeader"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("height"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint64"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("header"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("updateFunctionId"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("updateFunctionId"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("name"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::String,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("string"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("_functionId"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bytes32"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("updateGateway"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("updateGateway"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("_gateway"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Address,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("address"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::NonPayable,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("verifyMerkleProof"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Function {
                            name: ::std::borrow::ToOwned::to_owned("verifyMerkleProof"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("startBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(
                                        256usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint256"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("endBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(
                                        256usize,
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("uint256"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("_tuple"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                            ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct DataRootTuple"),
                                    ),
                                },
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("_proof"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Tuple(
                                        ::std::vec![
                                            ::ethers::core::abi::ethabi::ParamType::Array(
                                                ::std::boxed::Box::new(
                                                    ::ethers::core::abi::ethabi::ParamType::FixedBytes(32usize),
                                                ),
                                            ),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                            ::ethers::core::abi::ethabi::ParamType::Uint(256usize),
                                        ],
                                    ),
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("struct BinaryMerkleProof"),
                                    ),
                                },
                            ],
                            outputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::string::String::new(),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Bool,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("bool"),
                                    ),
                                },
                            ],
                            constant: ::core::option::Option::None,
                            state_mutability: ::ethers::core::abi::ethabi::StateMutability::View,
                        },
                    ],
                ),
            ]),
            events: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("CombinedSkipFulfilled"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "CombinedSkipFulfilled",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("startBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    indexed: true,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("targetBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    indexed: true,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("targetHeader"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    indexed: false,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("dataCommitment"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("CombinedSkipRequested"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "CombinedSkipRequested",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("startBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    indexed: true,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("targetBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    indexed: true,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("requestId"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("CombinedStepFulfilled"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "CombinedStepFulfilled",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("startBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    indexed: true,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("targetHeader"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    indexed: false,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("dataCommitment"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("CombinedStepRequested"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::Event {
                            name: ::std::borrow::ToOwned::to_owned(
                                "CombinedStepRequested",
                            ),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("startBlock"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::Uint(64usize),
                                    indexed: true,
                                },
                                ::ethers::core::abi::ethabi::EventParam {
                                    name: ::std::borrow::ToOwned::to_owned("requestId"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::FixedBytes(
                                        32usize,
                                    ),
                                    indexed: false,
                                },
                            ],
                            anonymous: false,
                        },
                    ],
                ),
            ]),
            errors: ::core::convert::From::from([
                (
                    ::std::borrow::ToOwned::to_owned("FunctionIdNotFound"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned("FunctionIdNotFound"),
                            inputs: ::std::vec![
                                ::ethers::core::abi::ethabi::Param {
                                    name: ::std::borrow::ToOwned::to_owned("name"),
                                    kind: ::ethers::core::abi::ethabi::ParamType::String,
                                    internal_type: ::core::option::Option::Some(
                                        ::std::borrow::ToOwned::to_owned("string"),
                                    ),
                                },
                            ],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("LatestHeaderNotFound"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned(
                                "LatestHeaderNotFound",
                            ),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("ProofBlockRangeTooLarge"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned(
                                "ProofBlockRangeTooLarge",
                            ),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
                (
                    ::std::borrow::ToOwned::to_owned("TargetLessThanLatest"),
                    ::std::vec![
                        ::ethers::core::abi::ethabi::AbiError {
                            name: ::std::borrow::ToOwned::to_owned(
                                "TargetLessThanLatest",
                            ),
                            inputs: ::std::vec![],
                        },
                    ],
                ),
            ]),
            receive: false,
            fallback: false,
        }
    }
    ///The parsed JSON ABI of the contract.
    pub static ZKBLOBSTREAM_ABI: ::ethers::contract::Lazy<::ethers::core::abi::Abi> = ::ethers::contract::Lazy::new(
        __abi,
    );
    #[rustfmt::skip]
    const __BYTECODE: &[u8] = b"`\x80`@R`\x01\x80T`\x01`\x01`@\x1B\x03\x19\x16a\x03\xE8\x17\x90U4\x80\x15a\0$W`\0\x80\xFD[P`@Qa\x17\xC78\x03\x80a\x17\xC7\x839\x81\x01`@\x81\x90Ra\0C\x91a\0hV[`\0\x80T`\x01`\x01`\xA0\x1B\x03\x19\x16`\x01`\x01`\xA0\x1B\x03\x92\x90\x92\x16\x91\x90\x91\x17\x90Ua\0\x98V[`\0` \x82\x84\x03\x12\x15a\0zW`\0\x80\xFD[\x81Q`\x01`\x01`\xA0\x1B\x03\x81\x16\x81\x14a\0\x91W`\0\x80\xFD[\x93\x92PPPV[a\x17 \x80a\0\xA7`\09`\0\xF3\xFE`\x80`@R`\x046\x10a\0\xFEW`\x005`\xE0\x1C\x80c\x8A4\xAA+\x11a\0\x95W\x80c\xB9\x1D\xEE\xB5\x11a\0dW\x80c\xB9\x1D\xEE\xB5\x14a\x02\xEAW\x80c\xC04k \x14a\x03\nW\x80c\xC3\xE5Qw\x14a\x03GW\x80c\xCE5;4\x14a\x03\x9DW\x80c\xD7\xE6\xC6\x8B\x14a\x03\xBDW`\0\x80\xFD[\x80c\x8A4\xAA+\x14a\x02eW\x80c\x96\x13\x9E\xBD\x14a\x02\x95W\x80c\xA6\x8Ab\xAE\x14a\x02\xC2W\x80c\xB0S\xE8\xB5\x14a\x02\xCAW`\0\x80\xFD[\x80c\":\xCF\xFE\x11a\0\xD1W\x80c\":\xCF\xFE\x14a\x01\xDAW\x80c9\xA4\xD8K\x14a\x01\xEFW\x80cG\x108N\x14a\x02\x0FW\x80cx\x80.\xF1\x14a\x02/W`\0\x80\xFD[\x80c\x07\xE2\xDA\x96\x14a\x01\x03W\x80c\x08\xE9>\xA5\x14a\x01GW\x80c\x11a\x91\xB6\x14a\x01\x82W\x80c \x15L}\x14a\x01\xBAW[`\0\x80\xFD[4\x80\x15a\x01\x0FW`\0\x80\xFD[P`\0Ta\x01*\x90`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x81V[`@Q`\x01`\x01`@\x1B\x03\x90\x91\x16\x81R` \x01[`@Q\x80\x91\x03\x90\xF3[4\x80\x15a\x01SW`\0\x80\xFD[Pa\x01ta\x01b6`\x04a\x10\x98V[`\x03` R`\0\x90\x81R`@\x90 T\x81V[`@Q\x90\x81R` \x01a\x01>V[4\x80\x15a\x01\x8EW`\0\x80\xFD[P`\0Ta\x01\xA2\x90`\x01`\x01`\xA0\x1B\x03\x16\x81V[`@Q`\x01`\x01`\xA0\x1B\x03\x90\x91\x16\x81R` \x01a\x01>V[4\x80\x15a\x01\xC6W`\0\x80\xFD[Pa\x01ta\x01\xD56`\x04a\x10\xB5V[a\x03\xF5V[a\x01\xEDa\x01\xE86`\x04a\x10\x98V[a\x04QV[\0[4\x80\x15a\x01\xFBW`\0\x80\xFD[Pa\x01\xEDa\x02\n6`\x04a\x11\xEDV[a\x06\xD1V[4\x80\x15a\x02\x1BW`\0\x80\xFD[P`\x01Ta\x01*\x90`\x01`\x01`@\x1B\x03\x16\x81V[4\x80\x15a\x02;W`\0\x80\xFD[Pa\x01ta\x02J6`\x04a\x10\x98V[`\x01`\x01`@\x1B\x03\x16`\0\x90\x81R`\x03` R`@\x90 T\x90V[4\x80\x15a\x02qW`\0\x80\xFD[Pa\x02\x85a\x02\x806`\x04a\x121V[a\x06\xF6V[`@Q\x90\x15\x15\x81R` \x01a\x01>V[4\x80\x15a\x02\xA1W`\0\x80\xFD[Pa\x01ta\x02\xB06`\x04a\x13\\V[`\x04` R`\0\x90\x81R`@\x90 T\x81V[a\x01\xEDa\x07\xADV[4\x80\x15a\x02\xD6W`\0\x80\xFD[Pa\x01\xEDa\x02\xE56`\x04a\x13uV[a\t\x97V[4\x80\x15a\x02\xF6W`\0\x80\xFD[Pa\x01\xEDa\x03\x056`\x04a\x13uV[a\n\xF0V[4\x80\x15a\x03\x16W`\0\x80\xFD[Pa\x01\xEDa\x03%6`\x04a\x13\xD8V[`\0\x80T`\x01`\x01`\xA0\x1B\x03\x19\x16`\x01`\x01`\xA0\x1B\x03\x92\x90\x92\x16\x91\x90\x91\x17\x90UV[4\x80\x15a\x03SW`\0\x80\xFD[Pa\x01\xEDa\x03b6`\x04a\x14\x01V[`\x01`\x01`@\x1B\x03\x91\x90\x91\x16`\0\x81\x81R`\x03` R`@\x81 \x92\x90\x92U\x81Tg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF`\xA0\x1B\x19\x16`\x01`\xA0\x1B\x90\x91\x02\x17\x90UV[4\x80\x15a\x03\xA9W`\0\x80\xFD[Pa\x01ta\x03\xB86`\x04a\x14-V[a\x0C9V[4\x80\x15a\x03\xC9W`\0\x80\xFD[Pa\x01ta\x03\xD86`\x04a\x14-V[\x80Q` \x81\x83\x01\x81\x01\x80Q`\x02\x82R\x92\x82\x01\x91\x90\x93\x01 \x91RT\x81V[`\0`\x04`\0\x84\x84`@Q` \x01a\x04#\x92\x91\x90`\x01`\x01`@\x1B\x03\x92\x83\x16\x81R\x91\x16` \x82\x01R`@\x01\x90V[`@Q` \x81\x83\x03\x03\x81R\x90`@R\x80Q\x90` \x01 \x81R` \x01\x90\x81R` \x01`\0 T\x90P[\x92\x91PPV[`\0\x80T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x81R`\x03` R`@\x90 T\x80a\x04\x8FW`@QcR\x06Z\xF9`\xE1\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0`\x02`@Qa\x04\xB2\x90k\x066\xF6\xD6&\x96\xE6VE6\xB6\x97`\xA4\x1B\x81R`\x0C\x01\x90V[\x90\x81R`@Q\x90\x81\x90\x03` \x01\x90 T\x90P\x80a\x05\x06W`@Qc\x1DF\x04\xEB`\xE1\x1B\x81R` `\x04\x82\x01R`\x0C`$\x82\x01Rk\x066\xF6\xD6&\x96\xE6VE6\xB6\x97`\xA4\x1B`D\x82\x01R`d\x01[`@Q\x80\x91\x03\x90\xFD[`\x01T`\0T`\x01`\x01`@\x1B\x03\x91\x82\x16\x91a\x05*\x91`\x01`\xA0\x1B\x90\x04\x16\x85a\x14wV[`\x01`\x01`@\x1B\x03\x16\x11\x15a\x05RW`@Qc\x0E\x9D\xA4\xF9`\xE2\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0T`\x01`\x01`@\x1B\x03`\x01`\xA0\x1B\x90\x91\x04\x81\x16\x90\x84\x16\x11a\x05\x88W`@Qc)\xE3E\x13`\xE0\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0\x80T`@\x80Q`\x01`\xA0\x1B\x83\x04`\xC0\x81\x81\x1B`\x01`\x01`\xC0\x1B\x03\x19\x90\x81\x16` \x85\x01R`(\x84\x01\x89\x90R\x90\x89\x90\x1B\x16`H\x83\x01R\x82Q`0\x81\x84\x03\x01\x81R`P\x83\x01\x84R`\x01`\x01`@\x1B\x03\x91\x82\x16`p\x84\x01R\x90\x88\x16`\x90\x80\x84\x01\x91\x90\x91R\x83Q\x80\x84\x03\x90\x91\x01\x81R`\xB0\x83\x01\x93\x84\x90Rc\xB3\xF0O\xDF`\xE0\x1B\x90\x93R`\x01`\x01`\xA0\x1B\x03\x90\x93\x16\x92c\xB3\xF0O\xDF\x924\x92a\x069\x92\x88\x92\x90\x91c\xB9\x1D\xEE\xB5`\xE0\x1B\x90b\x07\xA1 \x90`\xB4\x01a\x14\xE7V[` `@Q\x80\x83\x03\x81\x85\x88Z\xF1\x15\x80\x15a\x06WW=`\0\x80>=`\0\xFD[PPPPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\x06|\x91\x90a\x15<V[`\0T`@Q\x82\x81R\x91\x92P`\x01`\x01`@\x1B\x03\x86\x81\x16\x92`\x01`\xA0\x1B\x90\x92\x04\x16\x90\x7F\x01M\x97&!T\x9E%R}\x9Bs \x1F\xE7\x1C\x02\xEFPgihj\xFC\xDF\x81\xA9/{\x912\xEA\x90` \x01`@Q\x80\x91\x03\x90\xA3PPPPV[\x80`\x02\x83`@Qa\x06\xE2\x91\x90a\x15UV[\x90\x81R`@Q\x90\x81\x90\x03` \x01\x90 UPPV[`\0\x80T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x84\x11\x15a\x07\x19WP`\0a\x07\xA5V[`\0`\x04`\0\x87\x87`@Q` \x01a\x07;\x92\x91\x90\x91\x82R` \x82\x01R`@\x01\x90V[`@Q` \x81\x83\x03\x03\x81R\x90`@R\x80Q\x90` \x01 \x81R` \x01\x90\x81R` \x01`\0 T\x90P`\0a\x07\xA0\x82\x85\x87`@Q` \x01a\x07\x8C\x91\x90\x81Q\x81R` \x91\x82\x01Q\x91\x81\x01\x91\x90\x91R`@\x01\x90V[`@Q` \x81\x83\x03\x03\x81R\x90`@Ra\x0CaV[\x92PPP[\x94\x93PPPPV[`\0\x80T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x81R`\x03` R`@\x90 T\x80a\x07\xEBW`@QcR\x06Z\xF9`\xE1\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0`\x02`@Qa\x08\x0E\x90k\x066\xF6\xD6&\x96\xE6VE7FW`\xA4\x1B\x81R`\x0C\x01\x90V[\x90\x81R`@Q\x90\x81\x90\x03` \x01\x90 T\x90P\x80a\x08]W`@Qc\x1DF\x04\xEB`\xE1\x1B\x81R` `\x04\x82\x01R`\x0C`$\x82\x01Rk\x066\xF6\xD6&\x96\xE6VE7FW`\xA4\x1B`D\x82\x01R`d\x01a\x04\xFDV[`\0\x80T`@Q`\x01`\x01`\xC0\x1B\x03\x19`\x01`\xA0\x1B\x83\x04`\xC0\x1B\x16` \x82\x01R`(\x81\x01\x85\x90R`\x01`\x01`\xA0\x1B\x03\x90\x91\x16\x90c\xB3\xF0O\xDF\x904\x90\x85\x90`H\x01`@\x80Q\x80\x83\x03`\x1F\x19\x01\x81R\x82\x82R`\0T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16` \x84\x01R\x91\x01`@\x80Q`\x1F\x19\x81\x84\x03\x01\x81R\x90\x82\x90R`\x01`\x01`\xE0\x1B\x03\x19`\xE0\x87\x90\x1B\x16\x82Ra\t\x05\x93\x92\x91c\xB0S\xE8\xB5`\xE0\x1B\x90b\x07\xA1 \x90`\x04\x01a\x14\xE7V[` `@Q\x80\x83\x03\x81\x85\x88Z\xF1\x15\x80\x15a\t#W=`\0\x80>=`\0\xFD[PPPPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\tH\x91\x90a\x15<V[`\0T`@Q\x82\x81R\x91\x92P`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x90\x7FQ\xE8)@\xB6\x88\x85\x8E\xC5\xC8/l\x17\xE1F\xDB \x93\xBE\xC0\x94O`\xB0\xFD\x92\x13\x81\xEFt L\x90` \x01`@Q\x80\x91\x03\x90\xA2PPPV[`\0T`\x01`\x01`\xA0\x1B\x03\x163\x14a\t\xC1W`@QbF\x1B\xCD`\xE5\x1B\x81R`\x04\x01a\x04\xFD\x90a\x15qV[`\0\x81\x80` \x01\x90Q\x81\x01\x90a\t\xD7\x91\x90a\x15\xB4V[\x90P`\0\x80\x84\x80` \x01\x90Q\x81\x01\x90a\t\xF0\x91\x90a\x15\xD1V[\x90\x92P\x90P`\0a\n\x02\x84`\x01a\x15\xF5V[`\0T\x90\x91P`\x01`\x01`@\x1B\x03`\x01`\xA0\x1B\x90\x91\x04\x81\x16\x90\x82\x16\x11a\n;W`@Qc)\xE3E\x13`\xE0\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\x01`\x01`@\x1B\x03\x81\x81\x16`\0\x81\x81R`\x03` \x90\x81R`@\x80\x83 \x88\x90U\x80Q\x94\x89\x16\x85\x83\x01\x81\x90R\x85\x82\x01\x85\x90R\x81Q\x80\x87\x03\x83\x01\x81R``\x87\x01\x80\x84R\x81Q\x91\x85\x01\x91\x90\x91 \x85R`\x04\x90\x93R\x90\x83 \x87\x90U\x82Tg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF`\xA0\x1B\x19\x16`\x01`\xA0\x1B\x90\x94\x02\x93\x90\x93\x17\x90\x91U\x85\x90R`\x80\x82\x01\x84\x90R\x90\x7F\x88\n\xBA\xCB5\x15\xD6g\xADZZ\x9E\xE8\x8B\x02\x18\xEC\xA5\xD7\xBF-\x82Mi\xE7:\x01\xD7\xD3\x17\x03\x13\x90`\xA0\x01`@Q\x80\x91\x03\x90\xA2PPPPPPV[`\0T`\x01`\x01`\xA0\x1B\x03\x163\x14a\x0B\x1AW`@QbF\x1B\xCD`\xE5\x1B\x81R`\x04\x01a\x04\xFD\x90a\x15qV[`\0\x80\x82\x80` \x01\x90Q\x81\x01\x90a\x0B1\x91\x90a\x16\x15V[\x91P\x91P`\0\x80\x85\x80` \x01\x90Q\x81\x01\x90a\x0BL\x91\x90a\x15\xD1V[`\0T\x91\x93P\x91P`\x01`\x01`@\x1B\x03`\x01`\xA0\x1B\x90\x91\x04\x81\x16\x90\x84\x16\x11a\x0B\x87W`@Qc)\xE3E\x13`\xE0\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\x01`\x01`@\x1B\x03\x83\x81\x16`\0\x81\x81R`\x03` \x90\x81R`@\x80\x83 \x87\x90U\x80Q\x94\x89\x16\x85\x83\x01\x81\x90R\x85\x82\x01\x85\x90R\x81Q\x80\x87\x03\x83\x01\x81R``\x87\x01\x80\x84R\x81Q\x91\x85\x01\x91\x90\x91 \x85R`\x04\x90\x93R\x90\x83 \x86\x90U\x82Tg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF`\xA0\x1B\x19\x16`\x01`\xA0\x1B\x85\x02\x17\x90\x92U\x85\x90R`\x80\x83\x01\x84\x90R\x90\x91\x7F\xC2\xD8\x9D\x9B\x17\xFA\xE0\xDD\xB0G\xB2\x16N\x03v\x0Fu\xB6\xFE\xE6\xBD\xBB)\x1D\xD9\x86u\x19\xFFU\x819\x90`\xA0\x01`@Q\x80\x91\x03\x90\xA3PPPPPPV[`\0`\x02\x82`@Qa\x0CK\x91\x90a\x15UV[\x90\x81R` \x01`@Q\x80\x91\x03\x90 T\x90P\x91\x90PV[`\0`\x01\x83`@\x01Q\x11a\x0C\x84W\x82QQ\x15a\x0C\x7FWP`\0a\x0E\xCCV[a\x0C\xA6V[a\x0C\x96\x83` \x01Q\x84`@\x01Qa\x0E\xD3V[\x83QQ\x14a\x0C\xA6WP`\0a\x0E\xCCV[\x82`@\x01Q\x83` \x01Q\x10a\x0C\xBDWP`\0a\x0E\xCCV[`\0a\x0C\xC8\x83a\x0F`V[\x84QQ\x90\x91P`\0\x03a\x0C\xF4W\x83`@\x01Q`\x01\x03a\x0C\xEAW\x84\x14\x90Pa\x0E\xCCV[`\0\x91PPa\x0E\xCCV[` \x84\x01Q`\x01\x90[` \x86\x01Q`\0\x90`\x01\x84\x1B\x90a\r\x15\x90\x82\x90a\x16DV[a\r\x1F\x91\x90a\x16fV[\x90P`\0`\x01a\r1\x81\x86\x1B\x84a\x16}V[a\r;\x91\x90a\x16\x90V[\x90P\x87`@\x01Q\x81\x10a\rOWPPa\x0E\x15V[\x91P\x81a\r]`\x01\x85a\x16\x90V[\x88QQ\x11a\rsW`\0\x95PPPPPPa\x0E\xCCV[a\r~`\x01\x85a\x16\x90V[`\x01\x90\x1B\x82\x89` \x01Qa\r\x92\x91\x90a\x16\x90V[\x10\x15a\r\xCFW\x87Qa\r\xC8\x90\x86\x90a\r\xAB`\x01\x88a\x16\x90V[\x81Q\x81\x10a\r\xBBWa\r\xBBa\x16\xA3V[` \x02` \x01\x01Qa\x0F\xD5V[\x94Pa\x0E\x01V[\x87Qa\r\xFE\x90a\r\xE0`\x01\x87a\x16\x90V[\x81Q\x81\x10a\r\xF0Wa\r\xF0a\x16\xA3V[` \x02` \x01\x01Q\x86a\x0F\xD5V[\x94P[a\x0E\x0C`\x01\x85a\x16}V[\x93PPPa\x0C\xFDV[`\x01\x86`@\x01Qa\x0E&\x91\x90a\x16\x90V[\x81\x14a\x0EnWa\x0E7`\x01\x83a\x16\x90V[\x86QQ\x11a\x0EKW`\0\x93PPPPa\x0E\xCCV[\x85Qa\x0E^\x90\x84\x90a\r\xAB`\x01\x86a\x16\x90V[\x92Pa\x0Ek`\x01\x83a\x16}V[\x91P[\x85QQa\x0E|`\x01\x84a\x16\x90V[\x10\x15a\x0E\xC5W\x85Qa\x0E\xB1\x90a\x0E\x93`\x01\x85a\x16\x90V[\x81Q\x81\x10a\x0E\xA3Wa\x0E\xA3a\x16\xA3V[` \x02` \x01\x01Q\x84a\x0F\xD5V[\x92Pa\x0E\xBE`\x01\x83a\x16}V[\x91Pa\x0EnV[PP\x84\x14\x90P[\x93\x92PPPV[`\0a\x0E\xDE\x82a\x10SV[a\x0E\xEA\x90a\x01\0a\x16\x90V[\x90P`\0a\x0E\xF9`\x01\x83a\x16\x90V[`\x01\x90\x1B\x90P`\x01\x81a\x0F\x0C\x91\x90a\x16\x90V[\x84\x11a\x0F\x18WPa\x04KV[\x80`\x01\x03a\x0F*W`\x01\x91PPa\x04KV[a\x0FFa\x0F7\x82\x86a\x16\x90V[a\x0FA\x83\x86a\x16\x90V[a\x0E\xD3V[a\x0FQ\x90`\x01a\x16}V[\x91PPa\x04KV[P\x92\x91PPV[`\0`\x02`\0`\xF8\x1B\x83`@Q` \x01a\x0F{\x92\x91\x90a\x16\xB9V[`@\x80Q`\x1F\x19\x81\x84\x03\x01\x81R\x90\x82\x90Ra\x0F\x95\x91a\x15UV[` `@Q\x80\x83\x03\x81\x85Z\xFA\x15\x80\x15a\x0F\xB2W=`\0\x80>=`\0\xFD[PPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\x04K\x91\x90a\x15<V[`@Q`\x01`\xF8\x1B` \x82\x01R`!\x81\x01\x83\x90R`A\x81\x01\x82\x90R`\0\x90`\x02\x90`a\x01`@\x80Q`\x1F\x19\x81\x84\x03\x01\x81R\x90\x82\x90Ra\x10\x13\x91a\x15UV[` `@Q\x80\x83\x03\x81\x85Z\xFA\x15\x80\x15a\x100W=`\0\x80>=`\0\xFD[PPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\x0E\xCC\x91\x90a\x15<V[`\0[\x81\x81`\x01\x90\x1B\x10\x15a\x10tWa\x10m`\x01\x82a\x16}V[\x90Pa\x10VV[a\x04K\x81a\x01\0a\x16\x90V[`\x01`\x01`@\x1B\x03\x81\x16\x81\x14a\x10\x95W`\0\x80\xFD[PV[`\0` \x82\x84\x03\x12\x15a\x10\xAAW`\0\x80\xFD[\x815a\x0E\xCC\x81a\x10\x80V[`\0\x80`@\x83\x85\x03\x12\x15a\x10\xC8W`\0\x80\xFD[\x825a\x10\xD3\x81a\x10\x80V[\x91P` \x83\x015a\x10\xE3\x81a\x10\x80V[\x80\x91PP\x92P\x92\x90PV[cNH{q`\xE0\x1B`\0R`A`\x04R`$`\0\xFD[`@\x80Q\x90\x81\x01`\x01`\x01`@\x1B\x03\x81\x11\x82\x82\x10\x17\x15a\x11&Wa\x11&a\x10\xEEV[`@R\x90V[`@Q``\x81\x01`\x01`\x01`@\x1B\x03\x81\x11\x82\x82\x10\x17\x15a\x11&Wa\x11&a\x10\xEEV[`@Q`\x1F\x82\x01`\x1F\x19\x16\x81\x01`\x01`\x01`@\x1B\x03\x81\x11\x82\x82\x10\x17\x15a\x11vWa\x11va\x10\xEEV[`@R\x91\x90PV[`\0\x82`\x1F\x83\x01\x12a\x11\x8FW`\0\x80\xFD[\x815`\x01`\x01`@\x1B\x03\x81\x11\x15a\x11\xA8Wa\x11\xA8a\x10\xEEV[a\x11\xBB`\x1F\x82\x01`\x1F\x19\x16` \x01a\x11NV[\x81\x81R\x84` \x83\x86\x01\x01\x11\x15a\x11\xD0W`\0\x80\xFD[\x81` \x85\x01` \x83\x017`\0\x91\x81\x01` \x01\x91\x90\x91R\x93\x92PPPV[`\0\x80`@\x83\x85\x03\x12\x15a\x12\0W`\0\x80\xFD[\x825`\x01`\x01`@\x1B\x03\x81\x11\x15a\x12\x16W`\0\x80\xFD[a\x12\"\x85\x82\x86\x01a\x11~V[\x95` \x94\x90\x94\x015\x94PPPPV[`\0\x80`\0\x80\x84\x86\x03`\xA0\x81\x12\x15a\x12HW`\0\x80\xFD[\x855\x94P` \x80\x87\x015\x94P`@`?\x19\x83\x01\x12\x15a\x12fW`\0\x80\xFD[a\x12na\x11\x04V[`@\x88\x015\x81R``\x88\x015\x82\x82\x01R\x93P`\x80\x87\x015\x91P`\x01`\x01`@\x1B\x03\x80\x83\x11\x15a\x12\x9CW`\0\x80\xFD[\x91\x87\x01\x91``\x83\x8A\x03\x12\x15a\x12\xB0W`\0\x80\xFD[a\x12\xB8a\x11,V[\x835\x82\x81\x11\x15a\x12\xC7W`\0\x80\xFD[\x84\x01`\x1F\x81\x01\x8B\x13a\x12\xD8W`\0\x80\xFD[\x805\x83\x81\x11\x15a\x12\xEAWa\x12\xEAa\x10\xEEV[\x80`\x05\x1B\x93Pa\x12\xFB\x85\x85\x01a\x11NV[\x81\x81R\x93\x82\x01\x85\x01\x93\x85\x81\x01\x90\x8D\x86\x11\x15a\x13\x15W`\0\x80\xFD[\x92\x86\x01\x92[\x85\x84\x10\x15a\x133W\x835\x82R\x92\x86\x01\x92\x90\x86\x01\x90a\x13\x1AV[\x80\x85RPPPP\x82\x84\x015\x83\x82\x01R`@\x84\x015`@\x82\x01R\x80\x94PPPPP\x92\x95\x91\x94P\x92PV[`\0` \x82\x84\x03\x12\x15a\x13nW`\0\x80\xFD[P5\x91\x90PV[`\0\x80`@\x83\x85\x03\x12\x15a\x13\x88W`\0\x80\xFD[\x825`\x01`\x01`@\x1B\x03\x80\x82\x11\x15a\x13\x9FW`\0\x80\xFD[a\x13\xAB\x86\x83\x87\x01a\x11~V[\x93P` \x85\x015\x91P\x80\x82\x11\x15a\x13\xC1W`\0\x80\xFD[Pa\x13\xCE\x85\x82\x86\x01a\x11~V[\x91PP\x92P\x92\x90PV[`\0` \x82\x84\x03\x12\x15a\x13\xEAW`\0\x80\xFD[\x815`\x01`\x01`\xA0\x1B\x03\x81\x16\x81\x14a\x0E\xCCW`\0\x80\xFD[`\0\x80`@\x83\x85\x03\x12\x15a\x14\x14W`\0\x80\xFD[\x825a\x14\x1F\x81a\x10\x80V[\x94` \x93\x90\x93\x015\x93PPPV[`\0` \x82\x84\x03\x12\x15a\x14?W`\0\x80\xFD[\x815`\x01`\x01`@\x1B\x03\x81\x11\x15a\x14UW`\0\x80\xFD[a\x07\xA5\x84\x82\x85\x01a\x11~V[cNH{q`\xE0\x1B`\0R`\x11`\x04R`$`\0\xFD[`\x01`\x01`@\x1B\x03\x82\x81\x16\x82\x82\x16\x03\x90\x80\x82\x11\x15a\x0FYWa\x0FYa\x14aV[`\0[\x83\x81\x10\x15a\x14\xB2W\x81\x81\x01Q\x83\x82\x01R` \x01a\x14\x9AV[PP`\0\x91\x01RV[`\0\x81Q\x80\x84Ra\x14\xD3\x81` \x86\x01` \x86\x01a\x14\x97V[`\x1F\x01`\x1F\x19\x16\x92\x90\x92\x01` \x01\x92\x91PPV[\x85\x81R`\xA0` \x82\x01R`\0a\x15\0`\xA0\x83\x01\x87a\x14\xBBV[\x82\x81\x03`@\x84\x01Ra\x15\x12\x81\x87a\x14\xBBV[`\x01`\x01`\xE0\x1B\x03\x19\x95\x90\x95\x16``\x84\x01RPPc\xFF\xFF\xFF\xFF\x91\x90\x91\x16`\x80\x90\x91\x01R\x93\x92PPPV[`\0` \x82\x84\x03\x12\x15a\x15NW`\0\x80\xFD[PQ\x91\x90PV[`\0\x82Qa\x15g\x81\x84` \x87\x01a\x14\x97V[\x91\x90\x91\x01\x92\x91PPV[` \x80\x82R`#\x90\x82\x01R\x7FOnly gateway can call this funct`@\x82\x01Rb4\xB7\xB7`\xE9\x1B``\x82\x01R`\x80\x01\x90V[`\0` \x82\x84\x03\x12\x15a\x15\xC6W`\0\x80\xFD[\x81Qa\x0E\xCC\x81a\x10\x80V[`\0\x80`@\x83\x85\x03\x12\x15a\x15\xE4W`\0\x80\xFD[PP\x80Q` \x90\x91\x01Q\x90\x92\x90\x91PV[`\x01`\x01`@\x1B\x03\x81\x81\x16\x83\x82\x16\x01\x90\x80\x82\x11\x15a\x0FYWa\x0FYa\x14aV[`\0\x80`@\x83\x85\x03\x12\x15a\x16(W`\0\x80\xFD[\x82Qa\x163\x81a\x10\x80V[` \x84\x01Q\x90\x92Pa\x10\xE3\x81a\x10\x80V[`\0\x82a\x16aWcNH{q`\xE0\x1B`\0R`\x12`\x04R`$`\0\xFD[P\x04\x90V[\x80\x82\x02\x81\x15\x82\x82\x04\x84\x14\x17a\x04KWa\x04Ka\x14aV[\x80\x82\x01\x80\x82\x11\x15a\x04KWa\x04Ka\x14aV[\x81\x81\x03\x81\x81\x11\x15a\x04KWa\x04Ka\x14aV[cNH{q`\xE0\x1B`\0R`2`\x04R`$`\0\xFD[`\x01`\x01`\xF8\x1B\x03\x19\x83\x16\x81R\x81Q`\0\x90a\x16\xDC\x81`\x01\x85\x01` \x87\x01a\x14\x97V[\x91\x90\x91\x01`\x01\x01\x93\x92PPPV\xFE\xA2dipfsX\"\x12 \xEA\x94\x99\xBD\xC2\xE4\t=~\xD5|=f\xD8\x94Cd\xA0\x17\xD1\xDC\x03\xC4\xBE\xD1\xE0T\xAA\x12\xC2\xD6HdsolcC\0\x08\x15\x003";
    /// The bytecode of the contract.
    pub static ZKBLOBSTREAM_BYTECODE: ::ethers::core::types::Bytes = ::ethers::core::types::Bytes::from_static(
        __BYTECODE,
    );
    #[rustfmt::skip]
    const __DEPLOYED_BYTECODE: &[u8] = b"`\x80`@R`\x046\x10a\0\xFEW`\x005`\xE0\x1C\x80c\x8A4\xAA+\x11a\0\x95W\x80c\xB9\x1D\xEE\xB5\x11a\0dW\x80c\xB9\x1D\xEE\xB5\x14a\x02\xEAW\x80c\xC04k \x14a\x03\nW\x80c\xC3\xE5Qw\x14a\x03GW\x80c\xCE5;4\x14a\x03\x9DW\x80c\xD7\xE6\xC6\x8B\x14a\x03\xBDW`\0\x80\xFD[\x80c\x8A4\xAA+\x14a\x02eW\x80c\x96\x13\x9E\xBD\x14a\x02\x95W\x80c\xA6\x8Ab\xAE\x14a\x02\xC2W\x80c\xB0S\xE8\xB5\x14a\x02\xCAW`\0\x80\xFD[\x80c\":\xCF\xFE\x11a\0\xD1W\x80c\":\xCF\xFE\x14a\x01\xDAW\x80c9\xA4\xD8K\x14a\x01\xEFW\x80cG\x108N\x14a\x02\x0FW\x80cx\x80.\xF1\x14a\x02/W`\0\x80\xFD[\x80c\x07\xE2\xDA\x96\x14a\x01\x03W\x80c\x08\xE9>\xA5\x14a\x01GW\x80c\x11a\x91\xB6\x14a\x01\x82W\x80c \x15L}\x14a\x01\xBAW[`\0\x80\xFD[4\x80\x15a\x01\x0FW`\0\x80\xFD[P`\0Ta\x01*\x90`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x81V[`@Q`\x01`\x01`@\x1B\x03\x90\x91\x16\x81R` \x01[`@Q\x80\x91\x03\x90\xF3[4\x80\x15a\x01SW`\0\x80\xFD[Pa\x01ta\x01b6`\x04a\x10\x98V[`\x03` R`\0\x90\x81R`@\x90 T\x81V[`@Q\x90\x81R` \x01a\x01>V[4\x80\x15a\x01\x8EW`\0\x80\xFD[P`\0Ta\x01\xA2\x90`\x01`\x01`\xA0\x1B\x03\x16\x81V[`@Q`\x01`\x01`\xA0\x1B\x03\x90\x91\x16\x81R` \x01a\x01>V[4\x80\x15a\x01\xC6W`\0\x80\xFD[Pa\x01ta\x01\xD56`\x04a\x10\xB5V[a\x03\xF5V[a\x01\xEDa\x01\xE86`\x04a\x10\x98V[a\x04QV[\0[4\x80\x15a\x01\xFBW`\0\x80\xFD[Pa\x01\xEDa\x02\n6`\x04a\x11\xEDV[a\x06\xD1V[4\x80\x15a\x02\x1BW`\0\x80\xFD[P`\x01Ta\x01*\x90`\x01`\x01`@\x1B\x03\x16\x81V[4\x80\x15a\x02;W`\0\x80\xFD[Pa\x01ta\x02J6`\x04a\x10\x98V[`\x01`\x01`@\x1B\x03\x16`\0\x90\x81R`\x03` R`@\x90 T\x90V[4\x80\x15a\x02qW`\0\x80\xFD[Pa\x02\x85a\x02\x806`\x04a\x121V[a\x06\xF6V[`@Q\x90\x15\x15\x81R` \x01a\x01>V[4\x80\x15a\x02\xA1W`\0\x80\xFD[Pa\x01ta\x02\xB06`\x04a\x13\\V[`\x04` R`\0\x90\x81R`@\x90 T\x81V[a\x01\xEDa\x07\xADV[4\x80\x15a\x02\xD6W`\0\x80\xFD[Pa\x01\xEDa\x02\xE56`\x04a\x13uV[a\t\x97V[4\x80\x15a\x02\xF6W`\0\x80\xFD[Pa\x01\xEDa\x03\x056`\x04a\x13uV[a\n\xF0V[4\x80\x15a\x03\x16W`\0\x80\xFD[Pa\x01\xEDa\x03%6`\x04a\x13\xD8V[`\0\x80T`\x01`\x01`\xA0\x1B\x03\x19\x16`\x01`\x01`\xA0\x1B\x03\x92\x90\x92\x16\x91\x90\x91\x17\x90UV[4\x80\x15a\x03SW`\0\x80\xFD[Pa\x01\xEDa\x03b6`\x04a\x14\x01V[`\x01`\x01`@\x1B\x03\x91\x90\x91\x16`\0\x81\x81R`\x03` R`@\x81 \x92\x90\x92U\x81Tg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF`\xA0\x1B\x19\x16`\x01`\xA0\x1B\x90\x91\x02\x17\x90UV[4\x80\x15a\x03\xA9W`\0\x80\xFD[Pa\x01ta\x03\xB86`\x04a\x14-V[a\x0C9V[4\x80\x15a\x03\xC9W`\0\x80\xFD[Pa\x01ta\x03\xD86`\x04a\x14-V[\x80Q` \x81\x83\x01\x81\x01\x80Q`\x02\x82R\x92\x82\x01\x91\x90\x93\x01 \x91RT\x81V[`\0`\x04`\0\x84\x84`@Q` \x01a\x04#\x92\x91\x90`\x01`\x01`@\x1B\x03\x92\x83\x16\x81R\x91\x16` \x82\x01R`@\x01\x90V[`@Q` \x81\x83\x03\x03\x81R\x90`@R\x80Q\x90` \x01 \x81R` \x01\x90\x81R` \x01`\0 T\x90P[\x92\x91PPV[`\0\x80T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x81R`\x03` R`@\x90 T\x80a\x04\x8FW`@QcR\x06Z\xF9`\xE1\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0`\x02`@Qa\x04\xB2\x90k\x066\xF6\xD6&\x96\xE6VE6\xB6\x97`\xA4\x1B\x81R`\x0C\x01\x90V[\x90\x81R`@Q\x90\x81\x90\x03` \x01\x90 T\x90P\x80a\x05\x06W`@Qc\x1DF\x04\xEB`\xE1\x1B\x81R` `\x04\x82\x01R`\x0C`$\x82\x01Rk\x066\xF6\xD6&\x96\xE6VE6\xB6\x97`\xA4\x1B`D\x82\x01R`d\x01[`@Q\x80\x91\x03\x90\xFD[`\x01T`\0T`\x01`\x01`@\x1B\x03\x91\x82\x16\x91a\x05*\x91`\x01`\xA0\x1B\x90\x04\x16\x85a\x14wV[`\x01`\x01`@\x1B\x03\x16\x11\x15a\x05RW`@Qc\x0E\x9D\xA4\xF9`\xE2\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0T`\x01`\x01`@\x1B\x03`\x01`\xA0\x1B\x90\x91\x04\x81\x16\x90\x84\x16\x11a\x05\x88W`@Qc)\xE3E\x13`\xE0\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0\x80T`@\x80Q`\x01`\xA0\x1B\x83\x04`\xC0\x81\x81\x1B`\x01`\x01`\xC0\x1B\x03\x19\x90\x81\x16` \x85\x01R`(\x84\x01\x89\x90R\x90\x89\x90\x1B\x16`H\x83\x01R\x82Q`0\x81\x84\x03\x01\x81R`P\x83\x01\x84R`\x01`\x01`@\x1B\x03\x91\x82\x16`p\x84\x01R\x90\x88\x16`\x90\x80\x84\x01\x91\x90\x91R\x83Q\x80\x84\x03\x90\x91\x01\x81R`\xB0\x83\x01\x93\x84\x90Rc\xB3\xF0O\xDF`\xE0\x1B\x90\x93R`\x01`\x01`\xA0\x1B\x03\x90\x93\x16\x92c\xB3\xF0O\xDF\x924\x92a\x069\x92\x88\x92\x90\x91c\xB9\x1D\xEE\xB5`\xE0\x1B\x90b\x07\xA1 \x90`\xB4\x01a\x14\xE7V[` `@Q\x80\x83\x03\x81\x85\x88Z\xF1\x15\x80\x15a\x06WW=`\0\x80>=`\0\xFD[PPPPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\x06|\x91\x90a\x15<V[`\0T`@Q\x82\x81R\x91\x92P`\x01`\x01`@\x1B\x03\x86\x81\x16\x92`\x01`\xA0\x1B\x90\x92\x04\x16\x90\x7F\x01M\x97&!T\x9E%R}\x9Bs \x1F\xE7\x1C\x02\xEFPgihj\xFC\xDF\x81\xA9/{\x912\xEA\x90` \x01`@Q\x80\x91\x03\x90\xA3PPPPV[\x80`\x02\x83`@Qa\x06\xE2\x91\x90a\x15UV[\x90\x81R`@Q\x90\x81\x90\x03` \x01\x90 UPPV[`\0\x80T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x84\x11\x15a\x07\x19WP`\0a\x07\xA5V[`\0`\x04`\0\x87\x87`@Q` \x01a\x07;\x92\x91\x90\x91\x82R` \x82\x01R`@\x01\x90V[`@Q` \x81\x83\x03\x03\x81R\x90`@R\x80Q\x90` \x01 \x81R` \x01\x90\x81R` \x01`\0 T\x90P`\0a\x07\xA0\x82\x85\x87`@Q` \x01a\x07\x8C\x91\x90\x81Q\x81R` \x91\x82\x01Q\x91\x81\x01\x91\x90\x91R`@\x01\x90V[`@Q` \x81\x83\x03\x03\x81R\x90`@Ra\x0CaV[\x92PPP[\x94\x93PPPPV[`\0\x80T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x81R`\x03` R`@\x90 T\x80a\x07\xEBW`@QcR\x06Z\xF9`\xE1\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\0`\x02`@Qa\x08\x0E\x90k\x066\xF6\xD6&\x96\xE6VE7FW`\xA4\x1B\x81R`\x0C\x01\x90V[\x90\x81R`@Q\x90\x81\x90\x03` \x01\x90 T\x90P\x80a\x08]W`@Qc\x1DF\x04\xEB`\xE1\x1B\x81R` `\x04\x82\x01R`\x0C`$\x82\x01Rk\x066\xF6\xD6&\x96\xE6VE7FW`\xA4\x1B`D\x82\x01R`d\x01a\x04\xFDV[`\0\x80T`@Q`\x01`\x01`\xC0\x1B\x03\x19`\x01`\xA0\x1B\x83\x04`\xC0\x1B\x16` \x82\x01R`(\x81\x01\x85\x90R`\x01`\x01`\xA0\x1B\x03\x90\x91\x16\x90c\xB3\xF0O\xDF\x904\x90\x85\x90`H\x01`@\x80Q\x80\x83\x03`\x1F\x19\x01\x81R\x82\x82R`\0T`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16` \x84\x01R\x91\x01`@\x80Q`\x1F\x19\x81\x84\x03\x01\x81R\x90\x82\x90R`\x01`\x01`\xE0\x1B\x03\x19`\xE0\x87\x90\x1B\x16\x82Ra\t\x05\x93\x92\x91c\xB0S\xE8\xB5`\xE0\x1B\x90b\x07\xA1 \x90`\x04\x01a\x14\xE7V[` `@Q\x80\x83\x03\x81\x85\x88Z\xF1\x15\x80\x15a\t#W=`\0\x80>=`\0\xFD[PPPPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\tH\x91\x90a\x15<V[`\0T`@Q\x82\x81R\x91\x92P`\x01`\xA0\x1B\x90\x04`\x01`\x01`@\x1B\x03\x16\x90\x7FQ\xE8)@\xB6\x88\x85\x8E\xC5\xC8/l\x17\xE1F\xDB \x93\xBE\xC0\x94O`\xB0\xFD\x92\x13\x81\xEFt L\x90` \x01`@Q\x80\x91\x03\x90\xA2PPPV[`\0T`\x01`\x01`\xA0\x1B\x03\x163\x14a\t\xC1W`@QbF\x1B\xCD`\xE5\x1B\x81R`\x04\x01a\x04\xFD\x90a\x15qV[`\0\x81\x80` \x01\x90Q\x81\x01\x90a\t\xD7\x91\x90a\x15\xB4V[\x90P`\0\x80\x84\x80` \x01\x90Q\x81\x01\x90a\t\xF0\x91\x90a\x15\xD1V[\x90\x92P\x90P`\0a\n\x02\x84`\x01a\x15\xF5V[`\0T\x90\x91P`\x01`\x01`@\x1B\x03`\x01`\xA0\x1B\x90\x91\x04\x81\x16\x90\x82\x16\x11a\n;W`@Qc)\xE3E\x13`\xE0\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\x01`\x01`@\x1B\x03\x81\x81\x16`\0\x81\x81R`\x03` \x90\x81R`@\x80\x83 \x88\x90U\x80Q\x94\x89\x16\x85\x83\x01\x81\x90R\x85\x82\x01\x85\x90R\x81Q\x80\x87\x03\x83\x01\x81R``\x87\x01\x80\x84R\x81Q\x91\x85\x01\x91\x90\x91 \x85R`\x04\x90\x93R\x90\x83 \x87\x90U\x82Tg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF`\xA0\x1B\x19\x16`\x01`\xA0\x1B\x90\x94\x02\x93\x90\x93\x17\x90\x91U\x85\x90R`\x80\x82\x01\x84\x90R\x90\x7F\x88\n\xBA\xCB5\x15\xD6g\xADZZ\x9E\xE8\x8B\x02\x18\xEC\xA5\xD7\xBF-\x82Mi\xE7:\x01\xD7\xD3\x17\x03\x13\x90`\xA0\x01`@Q\x80\x91\x03\x90\xA2PPPPPPV[`\0T`\x01`\x01`\xA0\x1B\x03\x163\x14a\x0B\x1AW`@QbF\x1B\xCD`\xE5\x1B\x81R`\x04\x01a\x04\xFD\x90a\x15qV[`\0\x80\x82\x80` \x01\x90Q\x81\x01\x90a\x0B1\x91\x90a\x16\x15V[\x91P\x91P`\0\x80\x85\x80` \x01\x90Q\x81\x01\x90a\x0BL\x91\x90a\x15\xD1V[`\0T\x91\x93P\x91P`\x01`\x01`@\x1B\x03`\x01`\xA0\x1B\x90\x91\x04\x81\x16\x90\x84\x16\x11a\x0B\x87W`@Qc)\xE3E\x13`\xE0\x1B\x81R`\x04\x01`@Q\x80\x91\x03\x90\xFD[`\x01`\x01`@\x1B\x03\x83\x81\x16`\0\x81\x81R`\x03` \x90\x81R`@\x80\x83 \x87\x90U\x80Q\x94\x89\x16\x85\x83\x01\x81\x90R\x85\x82\x01\x85\x90R\x81Q\x80\x87\x03\x83\x01\x81R``\x87\x01\x80\x84R\x81Q\x91\x85\x01\x91\x90\x91 \x85R`\x04\x90\x93R\x90\x83 \x86\x90U\x82Tg\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF`\xA0\x1B\x19\x16`\x01`\xA0\x1B\x85\x02\x17\x90\x92U\x85\x90R`\x80\x83\x01\x84\x90R\x90\x91\x7F\xC2\xD8\x9D\x9B\x17\xFA\xE0\xDD\xB0G\xB2\x16N\x03v\x0Fu\xB6\xFE\xE6\xBD\xBB)\x1D\xD9\x86u\x19\xFFU\x819\x90`\xA0\x01`@Q\x80\x91\x03\x90\xA3PPPPPPV[`\0`\x02\x82`@Qa\x0CK\x91\x90a\x15UV[\x90\x81R` \x01`@Q\x80\x91\x03\x90 T\x90P\x91\x90PV[`\0`\x01\x83`@\x01Q\x11a\x0C\x84W\x82QQ\x15a\x0C\x7FWP`\0a\x0E\xCCV[a\x0C\xA6V[a\x0C\x96\x83` \x01Q\x84`@\x01Qa\x0E\xD3V[\x83QQ\x14a\x0C\xA6WP`\0a\x0E\xCCV[\x82`@\x01Q\x83` \x01Q\x10a\x0C\xBDWP`\0a\x0E\xCCV[`\0a\x0C\xC8\x83a\x0F`V[\x84QQ\x90\x91P`\0\x03a\x0C\xF4W\x83`@\x01Q`\x01\x03a\x0C\xEAW\x84\x14\x90Pa\x0E\xCCV[`\0\x91PPa\x0E\xCCV[` \x84\x01Q`\x01\x90[` \x86\x01Q`\0\x90`\x01\x84\x1B\x90a\r\x15\x90\x82\x90a\x16DV[a\r\x1F\x91\x90a\x16fV[\x90P`\0`\x01a\r1\x81\x86\x1B\x84a\x16}V[a\r;\x91\x90a\x16\x90V[\x90P\x87`@\x01Q\x81\x10a\rOWPPa\x0E\x15V[\x91P\x81a\r]`\x01\x85a\x16\x90V[\x88QQ\x11a\rsW`\0\x95PPPPPPa\x0E\xCCV[a\r~`\x01\x85a\x16\x90V[`\x01\x90\x1B\x82\x89` \x01Qa\r\x92\x91\x90a\x16\x90V[\x10\x15a\r\xCFW\x87Qa\r\xC8\x90\x86\x90a\r\xAB`\x01\x88a\x16\x90V[\x81Q\x81\x10a\r\xBBWa\r\xBBa\x16\xA3V[` \x02` \x01\x01Qa\x0F\xD5V[\x94Pa\x0E\x01V[\x87Qa\r\xFE\x90a\r\xE0`\x01\x87a\x16\x90V[\x81Q\x81\x10a\r\xF0Wa\r\xF0a\x16\xA3V[` \x02` \x01\x01Q\x86a\x0F\xD5V[\x94P[a\x0E\x0C`\x01\x85a\x16}V[\x93PPPa\x0C\xFDV[`\x01\x86`@\x01Qa\x0E&\x91\x90a\x16\x90V[\x81\x14a\x0EnWa\x0E7`\x01\x83a\x16\x90V[\x86QQ\x11a\x0EKW`\0\x93PPPPa\x0E\xCCV[\x85Qa\x0E^\x90\x84\x90a\r\xAB`\x01\x86a\x16\x90V[\x92Pa\x0Ek`\x01\x83a\x16}V[\x91P[\x85QQa\x0E|`\x01\x84a\x16\x90V[\x10\x15a\x0E\xC5W\x85Qa\x0E\xB1\x90a\x0E\x93`\x01\x85a\x16\x90V[\x81Q\x81\x10a\x0E\xA3Wa\x0E\xA3a\x16\xA3V[` \x02` \x01\x01Q\x84a\x0F\xD5V[\x92Pa\x0E\xBE`\x01\x83a\x16}V[\x91Pa\x0EnV[PP\x84\x14\x90P[\x93\x92PPPV[`\0a\x0E\xDE\x82a\x10SV[a\x0E\xEA\x90a\x01\0a\x16\x90V[\x90P`\0a\x0E\xF9`\x01\x83a\x16\x90V[`\x01\x90\x1B\x90P`\x01\x81a\x0F\x0C\x91\x90a\x16\x90V[\x84\x11a\x0F\x18WPa\x04KV[\x80`\x01\x03a\x0F*W`\x01\x91PPa\x04KV[a\x0FFa\x0F7\x82\x86a\x16\x90V[a\x0FA\x83\x86a\x16\x90V[a\x0E\xD3V[a\x0FQ\x90`\x01a\x16}V[\x91PPa\x04KV[P\x92\x91PPV[`\0`\x02`\0`\xF8\x1B\x83`@Q` \x01a\x0F{\x92\x91\x90a\x16\xB9V[`@\x80Q`\x1F\x19\x81\x84\x03\x01\x81R\x90\x82\x90Ra\x0F\x95\x91a\x15UV[` `@Q\x80\x83\x03\x81\x85Z\xFA\x15\x80\x15a\x0F\xB2W=`\0\x80>=`\0\xFD[PPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\x04K\x91\x90a\x15<V[`@Q`\x01`\xF8\x1B` \x82\x01R`!\x81\x01\x83\x90R`A\x81\x01\x82\x90R`\0\x90`\x02\x90`a\x01`@\x80Q`\x1F\x19\x81\x84\x03\x01\x81R\x90\x82\x90Ra\x10\x13\x91a\x15UV[` `@Q\x80\x83\x03\x81\x85Z\xFA\x15\x80\x15a\x100W=`\0\x80>=`\0\xFD[PPP`@Q=`\x1F\x19`\x1F\x82\x01\x16\x82\x01\x80`@RP\x81\x01\x90a\x0E\xCC\x91\x90a\x15<V[`\0[\x81\x81`\x01\x90\x1B\x10\x15a\x10tWa\x10m`\x01\x82a\x16}V[\x90Pa\x10VV[a\x04K\x81a\x01\0a\x16\x90V[`\x01`\x01`@\x1B\x03\x81\x16\x81\x14a\x10\x95W`\0\x80\xFD[PV[`\0` \x82\x84\x03\x12\x15a\x10\xAAW`\0\x80\xFD[\x815a\x0E\xCC\x81a\x10\x80V[`\0\x80`@\x83\x85\x03\x12\x15a\x10\xC8W`\0\x80\xFD[\x825a\x10\xD3\x81a\x10\x80V[\x91P` \x83\x015a\x10\xE3\x81a\x10\x80V[\x80\x91PP\x92P\x92\x90PV[cNH{q`\xE0\x1B`\0R`A`\x04R`$`\0\xFD[`@\x80Q\x90\x81\x01`\x01`\x01`@\x1B\x03\x81\x11\x82\x82\x10\x17\x15a\x11&Wa\x11&a\x10\xEEV[`@R\x90V[`@Q``\x81\x01`\x01`\x01`@\x1B\x03\x81\x11\x82\x82\x10\x17\x15a\x11&Wa\x11&a\x10\xEEV[`@Q`\x1F\x82\x01`\x1F\x19\x16\x81\x01`\x01`\x01`@\x1B\x03\x81\x11\x82\x82\x10\x17\x15a\x11vWa\x11va\x10\xEEV[`@R\x91\x90PV[`\0\x82`\x1F\x83\x01\x12a\x11\x8FW`\0\x80\xFD[\x815`\x01`\x01`@\x1B\x03\x81\x11\x15a\x11\xA8Wa\x11\xA8a\x10\xEEV[a\x11\xBB`\x1F\x82\x01`\x1F\x19\x16` \x01a\x11NV[\x81\x81R\x84` \x83\x86\x01\x01\x11\x15a\x11\xD0W`\0\x80\xFD[\x81` \x85\x01` \x83\x017`\0\x91\x81\x01` \x01\x91\x90\x91R\x93\x92PPPV[`\0\x80`@\x83\x85\x03\x12\x15a\x12\0W`\0\x80\xFD[\x825`\x01`\x01`@\x1B\x03\x81\x11\x15a\x12\x16W`\0\x80\xFD[a\x12\"\x85\x82\x86\x01a\x11~V[\x95` \x94\x90\x94\x015\x94PPPPV[`\0\x80`\0\x80\x84\x86\x03`\xA0\x81\x12\x15a\x12HW`\0\x80\xFD[\x855\x94P` \x80\x87\x015\x94P`@`?\x19\x83\x01\x12\x15a\x12fW`\0\x80\xFD[a\x12na\x11\x04V[`@\x88\x015\x81R``\x88\x015\x82\x82\x01R\x93P`\x80\x87\x015\x91P`\x01`\x01`@\x1B\x03\x80\x83\x11\x15a\x12\x9CW`\0\x80\xFD[\x91\x87\x01\x91``\x83\x8A\x03\x12\x15a\x12\xB0W`\0\x80\xFD[a\x12\xB8a\x11,V[\x835\x82\x81\x11\x15a\x12\xC7W`\0\x80\xFD[\x84\x01`\x1F\x81\x01\x8B\x13a\x12\xD8W`\0\x80\xFD[\x805\x83\x81\x11\x15a\x12\xEAWa\x12\xEAa\x10\xEEV[\x80`\x05\x1B\x93Pa\x12\xFB\x85\x85\x01a\x11NV[\x81\x81R\x93\x82\x01\x85\x01\x93\x85\x81\x01\x90\x8D\x86\x11\x15a\x13\x15W`\0\x80\xFD[\x92\x86\x01\x92[\x85\x84\x10\x15a\x133W\x835\x82R\x92\x86\x01\x92\x90\x86\x01\x90a\x13\x1AV[\x80\x85RPPPP\x82\x84\x015\x83\x82\x01R`@\x84\x015`@\x82\x01R\x80\x94PPPPP\x92\x95\x91\x94P\x92PV[`\0` \x82\x84\x03\x12\x15a\x13nW`\0\x80\xFD[P5\x91\x90PV[`\0\x80`@\x83\x85\x03\x12\x15a\x13\x88W`\0\x80\xFD[\x825`\x01`\x01`@\x1B\x03\x80\x82\x11\x15a\x13\x9FW`\0\x80\xFD[a\x13\xAB\x86\x83\x87\x01a\x11~V[\x93P` \x85\x015\x91P\x80\x82\x11\x15a\x13\xC1W`\0\x80\xFD[Pa\x13\xCE\x85\x82\x86\x01a\x11~V[\x91PP\x92P\x92\x90PV[`\0` \x82\x84\x03\x12\x15a\x13\xEAW`\0\x80\xFD[\x815`\x01`\x01`\xA0\x1B\x03\x81\x16\x81\x14a\x0E\xCCW`\0\x80\xFD[`\0\x80`@\x83\x85\x03\x12\x15a\x14\x14W`\0\x80\xFD[\x825a\x14\x1F\x81a\x10\x80V[\x94` \x93\x90\x93\x015\x93PPPV[`\0` \x82\x84\x03\x12\x15a\x14?W`\0\x80\xFD[\x815`\x01`\x01`@\x1B\x03\x81\x11\x15a\x14UW`\0\x80\xFD[a\x07\xA5\x84\x82\x85\x01a\x11~V[cNH{q`\xE0\x1B`\0R`\x11`\x04R`$`\0\xFD[`\x01`\x01`@\x1B\x03\x82\x81\x16\x82\x82\x16\x03\x90\x80\x82\x11\x15a\x0FYWa\x0FYa\x14aV[`\0[\x83\x81\x10\x15a\x14\xB2W\x81\x81\x01Q\x83\x82\x01R` \x01a\x14\x9AV[PP`\0\x91\x01RV[`\0\x81Q\x80\x84Ra\x14\xD3\x81` \x86\x01` \x86\x01a\x14\x97V[`\x1F\x01`\x1F\x19\x16\x92\x90\x92\x01` \x01\x92\x91PPV[\x85\x81R`\xA0` \x82\x01R`\0a\x15\0`\xA0\x83\x01\x87a\x14\xBBV[\x82\x81\x03`@\x84\x01Ra\x15\x12\x81\x87a\x14\xBBV[`\x01`\x01`\xE0\x1B\x03\x19\x95\x90\x95\x16``\x84\x01RPPc\xFF\xFF\xFF\xFF\x91\x90\x91\x16`\x80\x90\x91\x01R\x93\x92PPPV[`\0` \x82\x84\x03\x12\x15a\x15NW`\0\x80\xFD[PQ\x91\x90PV[`\0\x82Qa\x15g\x81\x84` \x87\x01a\x14\x97V[\x91\x90\x91\x01\x92\x91PPV[` \x80\x82R`#\x90\x82\x01R\x7FOnly gateway can call this funct`@\x82\x01Rb4\xB7\xB7`\xE9\x1B``\x82\x01R`\x80\x01\x90V[`\0` \x82\x84\x03\x12\x15a\x15\xC6W`\0\x80\xFD[\x81Qa\x0E\xCC\x81a\x10\x80V[`\0\x80`@\x83\x85\x03\x12\x15a\x15\xE4W`\0\x80\xFD[PP\x80Q` \x90\x91\x01Q\x90\x92\x90\x91PV[`\x01`\x01`@\x1B\x03\x81\x81\x16\x83\x82\x16\x01\x90\x80\x82\x11\x15a\x0FYWa\x0FYa\x14aV[`\0\x80`@\x83\x85\x03\x12\x15a\x16(W`\0\x80\xFD[\x82Qa\x163\x81a\x10\x80V[` \x84\x01Q\x90\x92Pa\x10\xE3\x81a\x10\x80V[`\0\x82a\x16aWcNH{q`\xE0\x1B`\0R`\x12`\x04R`$`\0\xFD[P\x04\x90V[\x80\x82\x02\x81\x15\x82\x82\x04\x84\x14\x17a\x04KWa\x04Ka\x14aV[\x80\x82\x01\x80\x82\x11\x15a\x04KWa\x04Ka\x14aV[\x81\x81\x03\x81\x81\x11\x15a\x04KWa\x04Ka\x14aV[cNH{q`\xE0\x1B`\0R`2`\x04R`$`\0\xFD[`\x01`\x01`\xF8\x1B\x03\x19\x83\x16\x81R\x81Q`\0\x90a\x16\xDC\x81`\x01\x85\x01` \x87\x01a\x14\x97V[\x91\x90\x91\x01`\x01\x01\x93\x92PPPV\xFE\xA2dipfsX\"\x12 \xEA\x94\x99\xBD\xC2\xE4\t=~\xD5|=f\xD8\x94Cd\xA0\x17\xD1\xDC\x03\xC4\xBE\xD1\xE0T\xAA\x12\xC2\xD6HdsolcC\0\x08\x15\x003";
    /// The deployed bytecode of the contract.
    pub static ZKBLOBSTREAM_DEPLOYED_BYTECODE: ::ethers::core::types::Bytes = ::ethers::core::types::Bytes::from_static(
        __DEPLOYED_BYTECODE,
    );
    pub struct ZKBlobstream<M>(::ethers::contract::Contract<M>);
    impl<M> ::core::clone::Clone for ZKBlobstream<M> {
        fn clone(&self) -> Self {
            Self(::core::clone::Clone::clone(&self.0))
        }
    }
    impl<M> ::core::ops::Deref for ZKBlobstream<M> {
        type Target = ::ethers::contract::Contract<M>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<M> ::core::ops::DerefMut for ZKBlobstream<M> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl<M> ::core::fmt::Debug for ZKBlobstream<M> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            f.debug_tuple(::core::stringify!(ZKBlobstream))
                .field(&self.address())
                .finish()
        }
    }
    impl<M: ::ethers::providers::Middleware> ZKBlobstream<M> {
        /// Creates a new contract instance with the specified `ethers` client at
        /// `address`. The contract derefs to a `ethers::Contract` object.
        pub fn new<T: Into<::ethers::core::types::Address>>(
            address: T,
            client: ::std::sync::Arc<M>,
        ) -> Self {
            Self(
                ::ethers::contract::Contract::new(
                    address.into(),
                    ZKBLOBSTREAM_ABI.clone(),
                    client,
                ),
            )
        }
        /// Constructs the general purpose `Deployer` instance based on the provided constructor arguments and sends it.
        /// Returns a new instance of a deployer that returns an instance of this contract after sending the transaction
        ///
        /// Notes:
        /// - If there are no constructor arguments, you should pass `()` as the argument.
        /// - The default poll duration is 7 seconds.
        /// - The default number of confirmations is 1 block.
        ///
        ///
        /// # Example
        ///
        /// Generate contract bindings with `abigen!` and deploy a new contract instance.
        ///
        /// *Note*: this requires a `bytecode` and `abi` object in the `greeter.json` artifact.
        ///
        /// ```ignore
        /// # async fn deploy<M: ethers::providers::Middleware>(client: ::std::sync::Arc<M>) {
        ///     abigen!(Greeter, "../greeter.json");
        ///
        ///    let greeter_contract = Greeter::deploy(client, "Hello world!".to_string()).unwrap().send().await.unwrap();
        ///    let msg = greeter_contract.greet().call().await.unwrap();
        /// # }
        /// ```
        pub fn deploy<T: ::ethers::core::abi::Tokenize>(
            client: ::std::sync::Arc<M>,
            constructor_args: T,
        ) -> ::core::result::Result<
            ::ethers::contract::builders::ContractDeployer<M, Self>,
            ::ethers::contract::ContractError<M>,
        > {
            let factory = ::ethers::contract::ContractFactory::new(
                ZKBLOBSTREAM_ABI.clone(),
                ZKBLOBSTREAM_BYTECODE.clone().into(),
                client,
            );
            let deployer = factory.deploy(constructor_args)?;
            let deployer = ::ethers::contract::ContractDeployer::new(deployer);
            Ok(deployer)
        }
        ///Calls the contract's `DATA_COMMITMENT_MAX` (0x4710384e) function
        pub fn data_commitment_max(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<M, u64> {
            self.0
                .method_hash([71, 16, 56, 78], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `blockHeightToHeaderHash` (0x08e93ea5) function
        pub fn block_height_to_header_hash(
            &self,
            p0: u64,
        ) -> ::ethers::contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([8, 233, 62, 165], p0)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `callbackCombinedSkip` (0xb91deeb5) function
        pub fn callback_combined_skip(
            &self,
            request_result: ::ethers::core::types::Bytes,
            context: ::ethers::core::types::Bytes,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([185, 29, 238, 181], (request_result, context))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `callbackCombinedStep` (0xb053e8b5) function
        pub fn callback_combined_step(
            &self,
            request_result: ::ethers::core::types::Bytes,
            context: ::ethers::core::types::Bytes,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([176, 83, 232, 181], (request_result, context))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `dataCommitments` (0x96139ebd) function
        pub fn data_commitments(
            &self,
            p0: [u8; 32],
        ) -> ::ethers::contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([150, 19, 158, 189], p0)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `functionNameToId` (0xd7e6c68b) function
        pub fn function_name_to_id(
            &self,
            p0: ::std::string::String,
        ) -> ::ethers::contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([215, 230, 198, 139], p0)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `gateway` (0x116191b6) function
        pub fn gateway(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<
            M,
            ::ethers::core::types::Address,
        > {
            self.0
                .method_hash([17, 97, 145, 182], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getDataCommitment` (0x20154c7d) function
        pub fn get_data_commitment(
            &self,
            start_block: u64,
            end_block: u64,
        ) -> ::ethers::contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([32, 21, 76, 125], (start_block, end_block))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getFunctionId` (0xce353b34) function
        pub fn get_function_id(
            &self,
            name: ::std::string::String,
        ) -> ::ethers::contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([206, 53, 59, 52], name)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getHeaderHash` (0x78802ef1) function
        pub fn get_header_hash(
            &self,
            height: u64,
        ) -> ::ethers::contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([120, 128, 46, 241], height)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `latestBlock` (0x07e2da96) function
        pub fn latest_block(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<M, u64> {
            self.0
                .method_hash([7, 226, 218, 150], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `requestCombinedSkip` (0x223acffe) function
        pub fn request_combined_skip(
            &self,
            requested_block: u64,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([34, 58, 207, 254], requested_block)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `requestCombinedStep` (0xa68a62ae) function
        pub fn request_combined_step(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([166, 138, 98, 174], ())
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `setGenesisHeader` (0xc3e55177) function
        pub fn set_genesis_header(
            &self,
            height: u64,
            header: [u8; 32],
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([195, 229, 81, 119], (height, header))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `updateFunctionId` (0x39a4d84b) function
        pub fn update_function_id(
            &self,
            name: ::std::string::String,
            function_id: [u8; 32],
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([57, 164, 216, 75], (name, function_id))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `updateGateway` (0xc0346b20) function
        pub fn update_gateway(
            &self,
            gateway: ::ethers::core::types::Address,
        ) -> ::ethers::contract::builders::ContractCall<M, ()> {
            self.0
                .method_hash([192, 52, 107, 32], gateway)
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `verifyMerkleProof` (0x8a34aa2b) function
        pub fn verify_merkle_proof(
            &self,
            start_block: ::ethers::core::types::U256,
            end_block: ::ethers::core::types::U256,
            tuple: DataRootTuple,
            proof: BinaryMerkleProof,
        ) -> ::ethers::contract::builders::ContractCall<M, bool> {
            self.0
                .method_hash([138, 52, 170, 43], (start_block, end_block, tuple, proof))
                .expect("method not found (this should never happen)")
        }
        ///Gets the contract's `CombinedSkipFulfilled` event
        pub fn combined_skip_fulfilled_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            CombinedSkipFulfilledFilter,
        > {
            self.0.event()
        }
        ///Gets the contract's `CombinedSkipRequested` event
        pub fn combined_skip_requested_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            CombinedSkipRequestedFilter,
        > {
            self.0.event()
        }
        ///Gets the contract's `CombinedStepFulfilled` event
        pub fn combined_step_fulfilled_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            CombinedStepFulfilledFilter,
        > {
            self.0.event()
        }
        ///Gets the contract's `CombinedStepRequested` event
        pub fn combined_step_requested_filter(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            CombinedStepRequestedFilter,
        > {
            self.0.event()
        }
        /// Returns an `Event` builder for all the events of this contract.
        pub fn events(
            &self,
        ) -> ::ethers::contract::builders::Event<
            ::std::sync::Arc<M>,
            M,
            ZKBlobstreamEvents,
        > {
            self.0.event_with_filter(::core::default::Default::default())
        }
    }
    impl<M: ::ethers::providers::Middleware> From<::ethers::contract::Contract<M>>
    for ZKBlobstream<M> {
        fn from(contract: ::ethers::contract::Contract<M>) -> Self {
            Self::new(contract.address(), contract.client())
        }
    }
    ///Custom Error type `FunctionIdNotFound` with signature `FunctionIdNotFound(string)` and selector `0x3a8c09d6`
    #[derive(
        Clone,
        ::ethers::contract::EthError,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "FunctionIdNotFound", abi = "FunctionIdNotFound(string)")]
    pub struct FunctionIdNotFound {
        pub name: ::std::string::String,
    }
    ///Custom Error type `LatestHeaderNotFound` with signature `LatestHeaderNotFound()` and selector `0xa40cb5f2`
    #[derive(
        Clone,
        ::ethers::contract::EthError,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "LatestHeaderNotFound", abi = "LatestHeaderNotFound()")]
    pub struct LatestHeaderNotFound;
    ///Custom Error type `ProofBlockRangeTooLarge` with signature `ProofBlockRangeTooLarge()` and selector `0x3a7693e4`
    #[derive(
        Clone,
        ::ethers::contract::EthError,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "ProofBlockRangeTooLarge", abi = "ProofBlockRangeTooLarge()")]
    pub struct ProofBlockRangeTooLarge;
    ///Custom Error type `TargetLessThanLatest` with signature `TargetLessThanLatest()` and selector `0x29e34513`
    #[derive(
        Clone,
        ::ethers::contract::EthError,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[etherror(name = "TargetLessThanLatest", abi = "TargetLessThanLatest()")]
    pub struct TargetLessThanLatest;
    ///Container type for all of the contract's custom errors
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        serde::Serialize,
        serde::Deserialize,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub enum ZKBlobstreamErrors {
        FunctionIdNotFound(FunctionIdNotFound),
        LatestHeaderNotFound(LatestHeaderNotFound),
        ProofBlockRangeTooLarge(ProofBlockRangeTooLarge),
        TargetLessThanLatest(TargetLessThanLatest),
        /// The standard solidity revert string, with selector
        /// Error(string) -- 0x08c379a0
        RevertString(::std::string::String),
    }
    impl ::ethers::core::abi::AbiDecode for ZKBlobstreamErrors {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded) = <::std::string::String as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::RevertString(decoded));
            }
            if let Ok(decoded) = <FunctionIdNotFound as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::FunctionIdNotFound(decoded));
            }
            if let Ok(decoded) = <LatestHeaderNotFound as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::LatestHeaderNotFound(decoded));
            }
            if let Ok(decoded) = <ProofBlockRangeTooLarge as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::ProofBlockRangeTooLarge(decoded));
            }
            if let Ok(decoded) = <TargetLessThanLatest as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::TargetLessThanLatest(decoded));
            }
            Err(::ethers::core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers::core::abi::AbiEncode for ZKBlobstreamErrors {
        fn encode(self) -> ::std::vec::Vec<u8> {
            match self {
                Self::FunctionIdNotFound(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::LatestHeaderNotFound(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::ProofBlockRangeTooLarge(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::TargetLessThanLatest(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::RevertString(s) => ::ethers::core::abi::AbiEncode::encode(s),
            }
        }
    }
    impl ::ethers::contract::ContractRevert for ZKBlobstreamErrors {
        fn valid_selector(selector: [u8; 4]) -> bool {
            match selector {
                [0x08, 0xc3, 0x79, 0xa0] => true,
                _ if selector
                    == <FunctionIdNotFound as ::ethers::contract::EthError>::selector() => {
                    true
                }
                _ if selector
                    == <LatestHeaderNotFound as ::ethers::contract::EthError>::selector() => {
                    true
                }
                _ if selector
                    == <ProofBlockRangeTooLarge as ::ethers::contract::EthError>::selector() => {
                    true
                }
                _ if selector
                    == <TargetLessThanLatest as ::ethers::contract::EthError>::selector() => {
                    true
                }
                _ => false,
            }
        }
    }
    impl ::core::fmt::Display for ZKBlobstreamErrors {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::FunctionIdNotFound(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::LatestHeaderNotFound(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::ProofBlockRangeTooLarge(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::TargetLessThanLatest(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::RevertString(s) => ::core::fmt::Display::fmt(s, f),
            }
        }
    }
    impl ::core::convert::From<::std::string::String> for ZKBlobstreamErrors {
        fn from(value: String) -> Self {
            Self::RevertString(value)
        }
    }
    impl ::core::convert::From<FunctionIdNotFound> for ZKBlobstreamErrors {
        fn from(value: FunctionIdNotFound) -> Self {
            Self::FunctionIdNotFound(value)
        }
    }
    impl ::core::convert::From<LatestHeaderNotFound> for ZKBlobstreamErrors {
        fn from(value: LatestHeaderNotFound) -> Self {
            Self::LatestHeaderNotFound(value)
        }
    }
    impl ::core::convert::From<ProofBlockRangeTooLarge> for ZKBlobstreamErrors {
        fn from(value: ProofBlockRangeTooLarge) -> Self {
            Self::ProofBlockRangeTooLarge(value)
        }
    }
    impl ::core::convert::From<TargetLessThanLatest> for ZKBlobstreamErrors {
        fn from(value: TargetLessThanLatest) -> Self {
            Self::TargetLessThanLatest(value)
        }
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "CombinedSkipFulfilled",
        abi = "CombinedSkipFulfilled(uint64,uint64,bytes32,bytes32)"
    )]
    pub struct CombinedSkipFulfilledFilter {
        #[ethevent(indexed)]
        pub start_block: u64,
        #[ethevent(indexed)]
        pub target_block: u64,
        pub target_header: [u8; 32],
        pub data_commitment: [u8; 32],
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "CombinedSkipRequested",
        abi = "CombinedSkipRequested(uint64,uint64,bytes32)"
    )]
    pub struct CombinedSkipRequestedFilter {
        #[ethevent(indexed)]
        pub start_block: u64,
        #[ethevent(indexed)]
        pub target_block: u64,
        pub request_id: [u8; 32],
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "CombinedStepFulfilled",
        abi = "CombinedStepFulfilled(uint64,bytes32,bytes32)"
    )]
    pub struct CombinedStepFulfilledFilter {
        #[ethevent(indexed)]
        pub start_block: u64,
        pub target_header: [u8; 32],
        pub data_commitment: [u8; 32],
    }
    #[derive(
        Clone,
        ::ethers::contract::EthEvent,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethevent(
        name = "CombinedStepRequested",
        abi = "CombinedStepRequested(uint64,bytes32)"
    )]
    pub struct CombinedStepRequestedFilter {
        #[ethevent(indexed)]
        pub start_block: u64,
        pub request_id: [u8; 32],
    }
    ///Container type for all of the contract's events
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        serde::Serialize,
        serde::Deserialize,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub enum ZKBlobstreamEvents {
        CombinedSkipFulfilledFilter(CombinedSkipFulfilledFilter),
        CombinedSkipRequestedFilter(CombinedSkipRequestedFilter),
        CombinedStepFulfilledFilter(CombinedStepFulfilledFilter),
        CombinedStepRequestedFilter(CombinedStepRequestedFilter),
    }
    impl ::ethers::contract::EthLogDecode for ZKBlobstreamEvents {
        fn decode_log(
            log: &::ethers::core::abi::RawLog,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::Error> {
            if let Ok(decoded) = CombinedSkipFulfilledFilter::decode_log(log) {
                return Ok(ZKBlobstreamEvents::CombinedSkipFulfilledFilter(decoded));
            }
            if let Ok(decoded) = CombinedSkipRequestedFilter::decode_log(log) {
                return Ok(ZKBlobstreamEvents::CombinedSkipRequestedFilter(decoded));
            }
            if let Ok(decoded) = CombinedStepFulfilledFilter::decode_log(log) {
                return Ok(ZKBlobstreamEvents::CombinedStepFulfilledFilter(decoded));
            }
            if let Ok(decoded) = CombinedStepRequestedFilter::decode_log(log) {
                return Ok(ZKBlobstreamEvents::CombinedStepRequestedFilter(decoded));
            }
            Err(::ethers::core::abi::Error::InvalidData)
        }
    }
    impl ::core::fmt::Display for ZKBlobstreamEvents {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::CombinedSkipFulfilledFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::CombinedSkipRequestedFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::CombinedStepFulfilledFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::CombinedStepRequestedFilter(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
            }
        }
    }
    impl ::core::convert::From<CombinedSkipFulfilledFilter> for ZKBlobstreamEvents {
        fn from(value: CombinedSkipFulfilledFilter) -> Self {
            Self::CombinedSkipFulfilledFilter(value)
        }
    }
    impl ::core::convert::From<CombinedSkipRequestedFilter> for ZKBlobstreamEvents {
        fn from(value: CombinedSkipRequestedFilter) -> Self {
            Self::CombinedSkipRequestedFilter(value)
        }
    }
    impl ::core::convert::From<CombinedStepFulfilledFilter> for ZKBlobstreamEvents {
        fn from(value: CombinedStepFulfilledFilter) -> Self {
            Self::CombinedStepFulfilledFilter(value)
        }
    }
    impl ::core::convert::From<CombinedStepRequestedFilter> for ZKBlobstreamEvents {
        fn from(value: CombinedStepRequestedFilter) -> Self {
            Self::CombinedStepRequestedFilter(value)
        }
    }
    ///Container type for all input parameters for the `DATA_COMMITMENT_MAX` function with signature `DATA_COMMITMENT_MAX()` and selector `0x4710384e`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "DATA_COMMITMENT_MAX", abi = "DATA_COMMITMENT_MAX()")]
    pub struct DataCommitmentMaxCall;
    ///Container type for all input parameters for the `blockHeightToHeaderHash` function with signature `blockHeightToHeaderHash(uint64)` and selector `0x08e93ea5`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "blockHeightToHeaderHash", abi = "blockHeightToHeaderHash(uint64)")]
    pub struct BlockHeightToHeaderHashCall(pub u64);
    ///Container type for all input parameters for the `callbackCombinedSkip` function with signature `callbackCombinedSkip(bytes,bytes)` and selector `0xb91deeb5`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "callbackCombinedSkip", abi = "callbackCombinedSkip(bytes,bytes)")]
    pub struct CallbackCombinedSkipCall {
        pub request_result: ::ethers::core::types::Bytes,
        pub context: ::ethers::core::types::Bytes,
    }
    ///Container type for all input parameters for the `callbackCombinedStep` function with signature `callbackCombinedStep(bytes,bytes)` and selector `0xb053e8b5`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "callbackCombinedStep", abi = "callbackCombinedStep(bytes,bytes)")]
    pub struct CallbackCombinedStepCall {
        pub request_result: ::ethers::core::types::Bytes,
        pub context: ::ethers::core::types::Bytes,
    }
    ///Container type for all input parameters for the `dataCommitments` function with signature `dataCommitments(bytes32)` and selector `0x96139ebd`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "dataCommitments", abi = "dataCommitments(bytes32)")]
    pub struct DataCommitmentsCall(pub [u8; 32]);
    ///Container type for all input parameters for the `functionNameToId` function with signature `functionNameToId(string)` and selector `0xd7e6c68b`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "functionNameToId", abi = "functionNameToId(string)")]
    pub struct FunctionNameToIdCall(pub ::std::string::String);
    ///Container type for all input parameters for the `gateway` function with signature `gateway()` and selector `0x116191b6`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "gateway", abi = "gateway()")]
    pub struct GatewayCall;
    ///Container type for all input parameters for the `getDataCommitment` function with signature `getDataCommitment(uint64,uint64)` and selector `0x20154c7d`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "getDataCommitment", abi = "getDataCommitment(uint64,uint64)")]
    pub struct GetDataCommitmentCall {
        pub start_block: u64,
        pub end_block: u64,
    }
    ///Container type for all input parameters for the `getFunctionId` function with signature `getFunctionId(string)` and selector `0xce353b34`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "getFunctionId", abi = "getFunctionId(string)")]
    pub struct GetFunctionIdCall {
        pub name: ::std::string::String,
    }
    ///Container type for all input parameters for the `getHeaderHash` function with signature `getHeaderHash(uint64)` and selector `0x78802ef1`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "getHeaderHash", abi = "getHeaderHash(uint64)")]
    pub struct GetHeaderHashCall {
        pub height: u64,
    }
    ///Container type for all input parameters for the `latestBlock` function with signature `latestBlock()` and selector `0x07e2da96`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "latestBlock", abi = "latestBlock()")]
    pub struct LatestBlockCall;
    ///Container type for all input parameters for the `requestCombinedSkip` function with signature `requestCombinedSkip(uint64)` and selector `0x223acffe`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "requestCombinedSkip", abi = "requestCombinedSkip(uint64)")]
    pub struct RequestCombinedSkipCall {
        pub requested_block: u64,
    }
    ///Container type for all input parameters for the `requestCombinedStep` function with signature `requestCombinedStep()` and selector `0xa68a62ae`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "requestCombinedStep", abi = "requestCombinedStep()")]
    pub struct RequestCombinedStepCall;
    ///Container type for all input parameters for the `setGenesisHeader` function with signature `setGenesisHeader(uint64,bytes32)` and selector `0xc3e55177`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "setGenesisHeader", abi = "setGenesisHeader(uint64,bytes32)")]
    pub struct SetGenesisHeaderCall {
        pub height: u64,
        pub header: [u8; 32],
    }
    ///Container type for all input parameters for the `updateFunctionId` function with signature `updateFunctionId(string,bytes32)` and selector `0x39a4d84b`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "updateFunctionId", abi = "updateFunctionId(string,bytes32)")]
    pub struct UpdateFunctionIdCall {
        pub name: ::std::string::String,
        pub function_id: [u8; 32],
    }
    ///Container type for all input parameters for the `updateGateway` function with signature `updateGateway(address)` and selector `0xc0346b20`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "updateGateway", abi = "updateGateway(address)")]
    pub struct UpdateGatewayCall {
        pub gateway: ::ethers::core::types::Address,
    }
    ///Container type for all input parameters for the `verifyMerkleProof` function with signature `verifyMerkleProof(uint256,uint256,(uint256,bytes32),(bytes32[],uint256,uint256))` and selector `0x8a34aa2b`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "verifyMerkleProof",
        abi = "verifyMerkleProof(uint256,uint256,(uint256,bytes32),(bytes32[],uint256,uint256))"
    )]
    pub struct VerifyMerkleProofCall {
        pub start_block: ::ethers::core::types::U256,
        pub end_block: ::ethers::core::types::U256,
        pub tuple: DataRootTuple,
        pub proof: BinaryMerkleProof,
    }
    ///Container type for all of the contract's call
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        serde::Serialize,
        serde::Deserialize,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub enum ZKBlobstreamCalls {
        DataCommitmentMax(DataCommitmentMaxCall),
        BlockHeightToHeaderHash(BlockHeightToHeaderHashCall),
        CallbackCombinedSkip(CallbackCombinedSkipCall),
        CallbackCombinedStep(CallbackCombinedStepCall),
        DataCommitments(DataCommitmentsCall),
        FunctionNameToId(FunctionNameToIdCall),
        Gateway(GatewayCall),
        GetDataCommitment(GetDataCommitmentCall),
        GetFunctionId(GetFunctionIdCall),
        GetHeaderHash(GetHeaderHashCall),
        LatestBlock(LatestBlockCall),
        RequestCombinedSkip(RequestCombinedSkipCall),
        RequestCombinedStep(RequestCombinedStepCall),
        SetGenesisHeader(SetGenesisHeaderCall),
        UpdateFunctionId(UpdateFunctionIdCall),
        UpdateGateway(UpdateGatewayCall),
        VerifyMerkleProof(VerifyMerkleProofCall),
    }
    impl ::ethers::core::abi::AbiDecode for ZKBlobstreamCalls {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded) = <DataCommitmentMaxCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::DataCommitmentMax(decoded));
            }
            if let Ok(decoded) = <BlockHeightToHeaderHashCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::BlockHeightToHeaderHash(decoded));
            }
            if let Ok(decoded) = <CallbackCombinedSkipCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::CallbackCombinedSkip(decoded));
            }
            if let Ok(decoded) = <CallbackCombinedStepCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::CallbackCombinedStep(decoded));
            }
            if let Ok(decoded) = <DataCommitmentsCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::DataCommitments(decoded));
            }
            if let Ok(decoded) = <FunctionNameToIdCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::FunctionNameToId(decoded));
            }
            if let Ok(decoded) = <GatewayCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::Gateway(decoded));
            }
            if let Ok(decoded) = <GetDataCommitmentCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetDataCommitment(decoded));
            }
            if let Ok(decoded) = <GetFunctionIdCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetFunctionId(decoded));
            }
            if let Ok(decoded) = <GetHeaderHashCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::GetHeaderHash(decoded));
            }
            if let Ok(decoded) = <LatestBlockCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::LatestBlock(decoded));
            }
            if let Ok(decoded) = <RequestCombinedSkipCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::RequestCombinedSkip(decoded));
            }
            if let Ok(decoded) = <RequestCombinedStepCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::RequestCombinedStep(decoded));
            }
            if let Ok(decoded) = <SetGenesisHeaderCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::SetGenesisHeader(decoded));
            }
            if let Ok(decoded) = <UpdateFunctionIdCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::UpdateFunctionId(decoded));
            }
            if let Ok(decoded) = <UpdateGatewayCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::UpdateGateway(decoded));
            }
            if let Ok(decoded) = <VerifyMerkleProofCall as ::ethers::core::abi::AbiDecode>::decode(
                data,
            ) {
                return Ok(Self::VerifyMerkleProof(decoded));
            }
            Err(::ethers::core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers::core::abi::AbiEncode for ZKBlobstreamCalls {
        fn encode(self) -> Vec<u8> {
            match self {
                Self::DataCommitmentMax(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::BlockHeightToHeaderHash(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::CallbackCombinedSkip(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::CallbackCombinedStep(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::DataCommitments(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::FunctionNameToId(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::Gateway(element) => ::ethers::core::abi::AbiEncode::encode(element),
                Self::GetDataCommitment(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::GetFunctionId(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::GetHeaderHash(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::LatestBlock(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::RequestCombinedSkip(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::RequestCombinedStep(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::SetGenesisHeader(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::UpdateFunctionId(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::UpdateGateway(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::VerifyMerkleProof(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
            }
        }
    }
    impl ::core::fmt::Display for ZKBlobstreamCalls {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::DataCommitmentMax(element) => ::core::fmt::Display::fmt(element, f),
                Self::BlockHeightToHeaderHash(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::CallbackCombinedSkip(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::CallbackCombinedStep(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::DataCommitments(element) => ::core::fmt::Display::fmt(element, f),
                Self::FunctionNameToId(element) => ::core::fmt::Display::fmt(element, f),
                Self::Gateway(element) => ::core::fmt::Display::fmt(element, f),
                Self::GetDataCommitment(element) => ::core::fmt::Display::fmt(element, f),
                Self::GetFunctionId(element) => ::core::fmt::Display::fmt(element, f),
                Self::GetHeaderHash(element) => ::core::fmt::Display::fmt(element, f),
                Self::LatestBlock(element) => ::core::fmt::Display::fmt(element, f),
                Self::RequestCombinedSkip(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::RequestCombinedStep(element) => {
                    ::core::fmt::Display::fmt(element, f)
                }
                Self::SetGenesisHeader(element) => ::core::fmt::Display::fmt(element, f),
                Self::UpdateFunctionId(element) => ::core::fmt::Display::fmt(element, f),
                Self::UpdateGateway(element) => ::core::fmt::Display::fmt(element, f),
                Self::VerifyMerkleProof(element) => ::core::fmt::Display::fmt(element, f),
            }
        }
    }
    impl ::core::convert::From<DataCommitmentMaxCall> for ZKBlobstreamCalls {
        fn from(value: DataCommitmentMaxCall) -> Self {
            Self::DataCommitmentMax(value)
        }
    }
    impl ::core::convert::From<BlockHeightToHeaderHashCall> for ZKBlobstreamCalls {
        fn from(value: BlockHeightToHeaderHashCall) -> Self {
            Self::BlockHeightToHeaderHash(value)
        }
    }
    impl ::core::convert::From<CallbackCombinedSkipCall> for ZKBlobstreamCalls {
        fn from(value: CallbackCombinedSkipCall) -> Self {
            Self::CallbackCombinedSkip(value)
        }
    }
    impl ::core::convert::From<CallbackCombinedStepCall> for ZKBlobstreamCalls {
        fn from(value: CallbackCombinedStepCall) -> Self {
            Self::CallbackCombinedStep(value)
        }
    }
    impl ::core::convert::From<DataCommitmentsCall> for ZKBlobstreamCalls {
        fn from(value: DataCommitmentsCall) -> Self {
            Self::DataCommitments(value)
        }
    }
    impl ::core::convert::From<FunctionNameToIdCall> for ZKBlobstreamCalls {
        fn from(value: FunctionNameToIdCall) -> Self {
            Self::FunctionNameToId(value)
        }
    }
    impl ::core::convert::From<GatewayCall> for ZKBlobstreamCalls {
        fn from(value: GatewayCall) -> Self {
            Self::Gateway(value)
        }
    }
    impl ::core::convert::From<GetDataCommitmentCall> for ZKBlobstreamCalls {
        fn from(value: GetDataCommitmentCall) -> Self {
            Self::GetDataCommitment(value)
        }
    }
    impl ::core::convert::From<GetFunctionIdCall> for ZKBlobstreamCalls {
        fn from(value: GetFunctionIdCall) -> Self {
            Self::GetFunctionId(value)
        }
    }
    impl ::core::convert::From<GetHeaderHashCall> for ZKBlobstreamCalls {
        fn from(value: GetHeaderHashCall) -> Self {
            Self::GetHeaderHash(value)
        }
    }
    impl ::core::convert::From<LatestBlockCall> for ZKBlobstreamCalls {
        fn from(value: LatestBlockCall) -> Self {
            Self::LatestBlock(value)
        }
    }
    impl ::core::convert::From<RequestCombinedSkipCall> for ZKBlobstreamCalls {
        fn from(value: RequestCombinedSkipCall) -> Self {
            Self::RequestCombinedSkip(value)
        }
    }
    impl ::core::convert::From<RequestCombinedStepCall> for ZKBlobstreamCalls {
        fn from(value: RequestCombinedStepCall) -> Self {
            Self::RequestCombinedStep(value)
        }
    }
    impl ::core::convert::From<SetGenesisHeaderCall> for ZKBlobstreamCalls {
        fn from(value: SetGenesisHeaderCall) -> Self {
            Self::SetGenesisHeader(value)
        }
    }
    impl ::core::convert::From<UpdateFunctionIdCall> for ZKBlobstreamCalls {
        fn from(value: UpdateFunctionIdCall) -> Self {
            Self::UpdateFunctionId(value)
        }
    }
    impl ::core::convert::From<UpdateGatewayCall> for ZKBlobstreamCalls {
        fn from(value: UpdateGatewayCall) -> Self {
            Self::UpdateGateway(value)
        }
    }
    impl ::core::convert::From<VerifyMerkleProofCall> for ZKBlobstreamCalls {
        fn from(value: VerifyMerkleProofCall) -> Self {
            Self::VerifyMerkleProof(value)
        }
    }
    ///Container type for all return fields from the `DATA_COMMITMENT_MAX` function with signature `DATA_COMMITMENT_MAX()` and selector `0x4710384e`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct DataCommitmentMaxReturn(pub u64);
    ///Container type for all return fields from the `blockHeightToHeaderHash` function with signature `blockHeightToHeaderHash(uint64)` and selector `0x08e93ea5`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct BlockHeightToHeaderHashReturn(pub [u8; 32]);
    ///Container type for all return fields from the `dataCommitments` function with signature `dataCommitments(bytes32)` and selector `0x96139ebd`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct DataCommitmentsReturn(pub [u8; 32]);
    ///Container type for all return fields from the `functionNameToId` function with signature `functionNameToId(string)` and selector `0xd7e6c68b`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct FunctionNameToIdReturn(pub [u8; 32]);
    ///Container type for all return fields from the `gateway` function with signature `gateway()` and selector `0x116191b6`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GatewayReturn(pub ::ethers::core::types::Address);
    ///Container type for all return fields from the `getDataCommitment` function with signature `getDataCommitment(uint64,uint64)` and selector `0x20154c7d`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetDataCommitmentReturn(pub [u8; 32]);
    ///Container type for all return fields from the `getFunctionId` function with signature `getFunctionId(string)` and selector `0xce353b34`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetFunctionIdReturn(pub [u8; 32]);
    ///Container type for all return fields from the `getHeaderHash` function with signature `getHeaderHash(uint64)` and selector `0x78802ef1`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetHeaderHashReturn(pub [u8; 32]);
    ///Container type for all return fields from the `latestBlock` function with signature `latestBlock()` and selector `0x07e2da96`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct LatestBlockReturn(pub u64);
    ///Container type for all return fields from the `verifyMerkleProof` function with signature `verifyMerkleProof(uint256,uint256,(uint256,bytes32),(bytes32[],uint256,uint256))` and selector `0x8a34aa2b`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        serde::Serialize,
        serde::Deserialize,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct VerifyMerkleProofReturn(pub bool);
}
