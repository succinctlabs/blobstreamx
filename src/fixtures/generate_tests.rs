use rand::Rng;
use reqwest::Error;
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use subtle_encoding::hex;
use tendermint::merkle::simple_hash_from_byte_vectors;

#[derive(Debug, Deserialize)]
struct Response {
    jsonrpc: String,
    id: i32,
    result: BlockData,
}

#[derive(Debug, Deserialize)]
struct BlockData {
    header: HeaderData,
    commit: CommitData,
    validator_set: ValidatorSetData,
}

#[derive(Debug, Deserialize)]
struct HeaderData {
    version: VersionData,
    chain_id: String,
    height: String,
}

#[derive(Debug, Deserialize)]
struct VersionData {
    block: String,
    app: String,
}

#[derive(Debug, Deserialize)]
struct CommitData {
    height: String,
    round: i32,
    block_id: BlockIdData,
    signatures: Vec<SignatureData>,
}

#[derive(Debug, Deserialize)]
struct BlockIdData {
    hash: String,
    parts: PartData,
}

#[derive(Debug, Deserialize)]
struct PartData {
    total: i32,
    hash: String,
}

#[derive(Debug, Deserialize)]
struct SignatureData {
    block_id_flag: i32,
    validator_address: String,
    timestamp: String,
    signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ValidatorSetData {
    validators: Vec<ValidatorData>,
    proposer: ValidatorData,
}

#[derive(Debug, Deserialize)]
struct ValidatorData {
    address: String,
    pub_key: PubkeyData,
    voting_power: String,
    proposer_priority: String,
}

#[derive(Debug, Deserialize)]
struct PubkeyData {
    r#type: String,
    value: String,
}

pub fn generate_val_array(num_validators: usize) {
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

pub async fn get_celestia_consensus_signatures() -> Result<(), Error> {
    // Read from https://rpc-t.celestia.nodestake.top/signed_block?height=131950 using
    // Serves latest block
    let url = "https://rpc-t.celestia.nodestake.top/signed_block";

    // Send a GET request and wait for the response

    // Convert response to string
    let res = reqwest::get(url).await?.text().await?;

    let v: Response = serde_json::from_str(&res).expect("Failed to parse JSON");

    for signature in v.result.commit.signatures {
        println!("Signature: {:?}", signature.signature);
    }

    // Parse the response body as JSON

    Ok(())
}
