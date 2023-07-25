use crate::merkle::simple_hash_from_byte_vectors;
use rand::Rng;
use sha2::Sha256;
use subtle_encoding::hex;

pub fn generate_tendermint_test_cases(num_validators: usize) {
    let mut rng = rand::thread_rng();
    // Generate an array of byte arrays where the byte arrays have variable length between 38 and 46 bytes and the total length of the array is less than n
    let random_bytes: Vec<Vec<u8>> = (0..num_validators)
        .map(|_| {
            let inner_length = rng.gen_range(38..=46);
            (0..inner_length).map(|_| rng.gen()).collect()
        })
        .collect();

    // Use simple_hash_from_byte_vectors to generate the root hash
    let root_hash = simple_hash_from_byte_vectors::<Sha256>(&random_bytes);

    // Print the random byte arrays as an array of hex strings, that have double quotes around them and are separated by commas

    let mut hex_strings = Vec::new();

    for b in &random_bytes {
        let hex_string = String::from_utf8(hex::encode(b)).expect("Found invalid UTF-8");
        hex_strings.push(hex_string);
    }

    // Format the hex strings with double quotes and commas
    println!("Validators: {:?}", hex_strings);

    // Print the root hash
    println!(
        "Root Hash: {:?}",
        String::from_utf8(hex::encode(root_hash)).expect("Found invalid UTF-8")
    );
}
