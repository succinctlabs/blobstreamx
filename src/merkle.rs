use digest::{consts::U32, Digest, FixedOutputReset};

pub const HASH_SIZE: usize = 32;

/// Hash is the output of the cryptographic digest function
pub type Hash = [u8; HASH_SIZE];

/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
/// Implementation of Merkle tree hashing for Tendermint.
pub trait MerkleHash {
    // tmhash({})
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn empty_hash(&mut self) -> Hash;

    // tmhash(0x00 || leaf)
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn leaf_hash(&mut self, bytes: &[u8]) -> Hash;

    // tmhash(0x01 || left || right)
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn inner_hash(&mut self, left: Hash, right: Hash) -> Hash;

    // Implements recursion into subtrees.
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn hash_byte_vectors(&mut self, byte_vecs: &[impl AsRef<[u8]>]) -> Hash {
        let length = byte_vecs.len();
        match length {
            0 => self.empty_hash(),
            1 => self.leaf_hash(byte_vecs[0].as_ref()),
            _ => {
                let split = length.next_power_of_two() / 2;
                let left = self.hash_byte_vectors(&byte_vecs[..split]);
                let right = self.hash_byte_vectors(&byte_vecs[split..]);
                self.inner_hash(left, right)
            },
        }
    }
}

// A helper to copy GenericArray into the human-friendly Hash type.
fn copy_to_hash(output: impl AsRef<[u8]>) -> Hash {
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(output.as_ref());
    hash_bytes
}

impl<H> MerkleHash for H
where
    H: Digest<OutputSize = U32> + FixedOutputReset,
{
    fn empty_hash(&mut self) -> Hash {
        // Get the output of an empty digest state.
        let digest = self.finalize_reset();
        copy_to_hash(digest)
    }

    fn leaf_hash(&mut self, bytes: &[u8]) -> Hash {
        // Feed the data to the hasher, prepended with 0x00.
        Digest::update(self, [0x00]);
        Digest::update(self, bytes);

        // Finalize the digest, reset the hasher state.
        let digest = self.finalize_reset();

        copy_to_hash(digest)
    }

    fn inner_hash(&mut self, left: Hash, right: Hash) -> Hash {
        // Feed the data to the hasher: 0x1, then left and right data.
        Digest::update(self, [0x01]);
        Digest::update(self, left);
        Digest::update(self, right);

        // Finalize the digest, reset the hasher state
        let digest = self.finalize_reset();

        copy_to_hash(digest)
    }
}

/// Compute a simple Merkle root from vectors of arbitrary byte vectors.
/// The leaves of the tree are the bytes of the given byte vectors in
/// the given order.
pub fn simple_hash_from_byte_vectors<H>(byte_vecs: &[impl AsRef<[u8]>]) -> Hash
where
    H: MerkleHash + Default,
{
    let mut hasher = H::default();
    hasher.hash_byte_vectors(byte_vecs)
}

#[cfg(test)]
pub(crate) mod tests {
    use sha2::Sha256;
    use subtle_encoding::hex;
    use super::*;

    #[test]
    fn test_validator_inclusion() {
        // These are test cases generated from querying `cosmos-hub`
        // for the validator set at height 0 for validator 0.

        // let root_hash = [125u8, 130, 148, 137, 132, 154, 188, 169, 153, 181, 72, 1, 150, 95, 7, 68, 137, 114, 181, 223, 226, 151, 52, 72, 170, 185, 171, 167, 154, 96, 187, 240];
        // Total: 180
        let leaf_root_hex = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56";
        let leaf_string = "L123456";

        let leaf_root = &hex::decode(leaf_root_hex).unwrap();
        let leaf_tree: Vec<Vec<u8>> = vec![leaf_string.as_bytes().to_vec(); 1];

        let root = simple_hash_from_byte_vectors::<Sha256>(&leaf_tree);
        assert_eq!(leaf_root, &root);
        
    }

    #[test]
    fn test_multiple_validator_inclusion() {
        // These are test cases generated from generating a random set of validators using the tendermint repository.

        // Serde JSON
        let leaf_root_hex = "15a56f297c4b7bb5c46e68bfb37dbbc3fda9706a812a6df5be7da82b92ed2b96";

        // JSON string
        let validators = vec![
        "d2ff400d808ac92a5aaef2ae0b89da3a0c5f81c31d8045f64ab56a5665213d3e",
        "daf22f6ea4fd7212471705d313aa74cea7a57142b2a7036e1d56ff3bf8881907",
        "af7a0db4fda681cb9c7df6610fc9befbd77a33b3c50cf72df42669383474a5be",
        "d15da7162c685b438bec174e725113fe4687b262756d0e3f1dfd3fb117e0206b",
        "09012f01d010bfe40ca9764c7197feec845e38eb965b2cc43c3b5faee3dc5a53",
        "4745a005866acbd7419be29832145fa3b244301c7bcb5de6c81817337d8bb0e9",
        "683d3b02ae93f118ebbb1b50d65c5d1df1e1cdc5331db23460c818df66fd80c9",
        "d3ce66f18a21a75ba85ea423973d22e34a9f416db9fad4cb627a840327816cfe",
        "b5a84ff7fff8767d474b06c5b5793f749d9cdac59420ae5b4b1d8eacec98a0c5",
        "33e566e90cad7121759efdfb6762a316570579d7dc2c35ad2fdadbe026618620",
        ];

        // Process the JSON value
        for validator in &validators {
            println!("Validator: {}", validator);
        }

        let bytes_vec: Vec<Vec<u8>> = validators
        .iter()
        .map(|s| hex::decode(s).unwrap())
        .collect();

        let leaf_root = &hex::decode(leaf_root_hex).unwrap();
        let leaf_tree: Vec<Vec<u8>> = bytes_vec;

        let root = simple_hash_from_byte_vectors::<Sha256>(&leaf_tree);
        assert_eq!(leaf_root, &root);
            
    }

}
