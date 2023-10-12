///`BinaryMerkleProof(bytes32[],uint256,uint256)`
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
pub struct BinaryMerkleProof {
    pub side_nodes: ::std::vec::Vec<[u8; 32]>,
    pub key: ::ethers::core::types::U256,
    pub num_leaves: ::ethers::core::types::U256,
}
///`DataRootTuple(uint256,bytes32)`
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
pub struct DataRootTuple {
    pub height: ::ethers::core::types::U256,
    pub data_root: [u8; 32],
}
