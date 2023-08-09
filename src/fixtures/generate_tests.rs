use crate::merkle::{SignedBlock, TempSignedBlock};
use rand::Rng;
use reqwest::Error;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fs::File, io::Write};
use subtle_encoding::hex;
use tendermint::{
    merkle::simple_hash_from_byte_vectors,
    validator::Set as ValidatorSet,
};

#[derive(Debug, Deserialize)]
struct Response {
    _jsonrpc: String,
    _id: i32,
    result: TempSignedBlock,
}

#[derive(Debug, Serialize, Deserialize)]
struct VerifySignatureData {
    pubkey: String,
    signature: String,
    message: String,
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
    let height = 11000;
    let mut url = "http://rpc.testnet.celestia.citizencosmos.space/signed_block?height=".to_string();
    url.push_str(height.to_string().as_str());

    // Send a GET request and wait for the response

    // Convert response to string
    let res = reqwest::get(url).await?.text().await?;

    let v: Response = serde_json::from_str(&res).expect("Failed to parse JSON");

    let temp_block = v.result;

    // Cast to SignedBlock
    let block = SignedBlock {
        header: temp_block.header,
        data: temp_block.data,
        commit: temp_block.commit,
        validator_set: ValidatorSet::new(
            temp_block.validator_set.validators,
            temp_block.validator_set.proposer,
        ),
    };

    println!("here");

    // Write to JSON file
    let json = serde_json::to_string(&block).unwrap();

    let mut path = "src/fixtures/".to_string();
    path.push_str(height.to_string().as_str());
    path.push_str("/signed_block.json");
    println!("Path: {:?}", path);
    let mut file = File::create(path).unwrap();
    file.write_all(json.as_bytes()).unwrap();

    Ok(())

    // let block: SignedBlock = v.result.try_into().expect("Failed to parse JSON");

    // let non_absent_votes =
    //     block
    //         .commit
    //         .signatures
    //         .iter()
    //         .enumerate()
    //         .filter_map(|(idx, signature)| {
    //             ValidatorIndex::try_from(idx)
    //                 .ok()
    //                 .and_then(|validator_idx| {
    //                     non_absent_vote(signature, validator_idx, &block.commit)
    //                         .map(|vote| (signature, vote))
    //                 })
    //         });

    // let mut signature_verify_data = Vec::new();
    // for (_, vote) in non_absent_votes {
    //     let validator = Box::new(
    //         match block.validator_set.validator(vote.validator_address) {
    //             Some(validator) => validator,
    //             None => continue, // Cannot find matching validator, so we skip the vote
    //         },
    //     );

    //     // Cast the vote into a signedVote struct (which is used to get the signed bytes)
    //     let signed_vote = Box::new(
    //         SignedVote::from_vote(vote.clone(), block.header.chain_id.clone())
    //             .expect("missing signature"),
    //     );

    //     let pub_key = validator.pub_key.ed25519().unwrap();

    //     // Get the encoded signed vote bytes
    //     // https://github.com/celestiaorg/celestia-core/blob/main/proto/tendermint/types/canonical.proto#L30-L37
    //     let sign_bytes = signed_vote.sign_bytes();

    //     // Similar to encoding the vote: https://github.com/informalsystems/tendermint-rs/blob/c2b5c9e01eab1c740598aa14375a7453f3bfa436/tendermint/src/vote.rs#L267-L271
    //     // let decoded_vote: CanonicalVote = Protobuf::<RawCanonicalVote>::decode_length_delimited_vec(&sign_bytes).expect("failed to decode sign_bytes");

    //     // Verify that the message signed is in fact the sign_bytes
    //     validator
    //         .verify_signature::<tendermint::crypto::default::signature::Verifier>(
    //             &sign_bytes,
    //             signed_vote.signature(),
    //         )
    //         .expect("invalid signature");

    //     let pubkey_str = String::from_utf8(hex::encode(pub_key.as_bytes())).unwrap();
    //     println!("Pubkey: {:?}", pubkey_str);
    //     let message_str = String::from_utf8(hex::encode(sign_bytes.clone())).unwrap();
    //     println!("Signed Vote: {:?}", message_str);
    //     let signature_bytes = signed_vote.signature().clone().into_bytes();
    //     let signature_str = String::from_utf8(hex::encode(signature_bytes.clone())).unwrap();
    //     println!("Signature: {:?}", signature_str);

    //     // Add pubkey, signed vote, signature into JSON object
    //     signature_verify_data.push(VerifySignatureData {
    //         pubkey: pubkey_str,
    //         signature: signature_str,
    //         message: message_str,
    //     });
    //     // TODO: We can break out of the loop when we have enough voting power.
    //     // See https://github.com/informalsystems/tendermint-rs/issues/235
    // }

    // // Write to JSON file
    // let json = serde_json::to_string(&signature_verify_data).unwrap();
    // // Write to file named "signature_verify_data.json"
    // let mut file = File::create("src/fixtures/signature_verify_data.json").unwrap();
    // file.write_all(json.as_bytes()).unwrap();

    // Ok(())
}
