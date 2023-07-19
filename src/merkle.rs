use digest::{consts::U32, Digest, FixedOutputReset};

pub const HASH_SIZE: usize = 32;

pub const HASH_LEN_BITS: usize = HASH_SIZE * 8;

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
            }
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
    use super::*;
    use sha2::Sha256;
    use subtle_encoding::hex;

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
        let leaf_root_hex = "168b0b14b4b10af44bd73a62f6b4bf10b72ef7669bb2b803cc8f23f37dd04b09";

        // JSON string
        let validators = vec![
            "54eefe7a464e6c67120dac79a0adba06a364faa37bcf0d72896bf604777732048a3964e9a509",
            "d9ff2bcdeb3433412649137bddfebf1fe92baa3f06a80815fca91c82e573546e8a4d9fd3fbd9",
            "f538cc8b62f6286f8b38d25dfe74be1a3488eebb2efda8d0a824bd250cfa0c7fd1db98ee5d19",
            "8423095697b74f57a8ea760881d163125f827ec62d025822addd2fdb15c7d26222182b2211d9",
            "480184c90e4e62e3fe59d51161e15057b96538951ddd54ce3946bcff54fa12bde6444c36b3f6",
            "237f40dcfe69210f3eb0ca400f86309a0e5e2d57d5b4d170b267f6f772f0734e0e3aa912ccf3",
            "bf808daaf1767dc2f3b067002c867c6fe46e8f825f763bf5db1f3e1e80df60870f9afe8817bb",
            "b463d92ecea817c4461608b0d15bb69b816a0551ccaa840cd4fd3be35b2f73325ec114ff9e26",
            "3499498f2f6ba09f67276826f7712df24325806a478b179f70dd63ed2d4033f955174d44b23d",
            "5bb1996443c9d5641b1eb3d7e683712f5c97e8e5644a87b094814f27f410a85c8c0706a841a8",
        ];

        // Process the JSON value
        for validator in &validators {
            println!("Validator: {}", validator);
        }

        let bytes_vec: Vec<Vec<u8>> = validators.iter().map(|s| hex::decode(s).unwrap()).collect();

        let leaf_root = &hex::decode(leaf_root_hex).unwrap();
        let leaf_tree: Vec<Vec<u8>> = bytes_vec;

        let root = simple_hash_from_byte_vectors::<Sha256>(&leaf_tree);
        assert_eq!(leaf_root, &root);
    }
}
