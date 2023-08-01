pub mod merkle;
pub mod scripts;
pub mod utils;
pub mod validator;

use crate::scripts::generate_tests;

use clap::Parser;

#[derive(Parser, Debug)]
enum Function {
    /// Calls the generate_val_array function
    GenerateValArray {
        /// Number of validators to generate test cases for
        #[clap(short, long)]
        validators: usize,
    },
    /// Calls the get_celestia_consensus_signatures function
    GetCelestiaConsensusSignatures,
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Script to run
    #[clap(subcommand)]
    function: Function,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    match args.function {
        Function::GenerateValArray { validators } => {
            println!("Number of validators: {}", validators);
            generate_tests::generate_val_array(validators);
        }
        Function::GetCelestiaConsensusSignatures => {
            generate_tests::get_celestia_consensus_signatures()
                .await
                .expect("Failed to get Celestia consensus signatures");
        }
    }
}
