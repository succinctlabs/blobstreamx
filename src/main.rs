pub mod fixture;
pub mod inputs;
pub mod signature;
pub mod utils;
pub mod validator;
pub mod verify;
pub mod voting;

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
    CreateNewFixture {
        /// The block number to create a new fixture for
        #[clap(short, long)]
        block: usize,
    },
    /// Generates step inputs
    GenerateStepInputs {
        /// Number of validators to generate test cases for
        #[clap(short, long)]
        block: usize,
    },
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
            fixture::generate_val_array(validators);
        }
        Function::CreateNewFixture { block } => {
            fixture::create_new_fixture(block)
                .await
                .expect("Failed to create new fixture");
        }
        Function::GenerateStepInputs { block } => {
            const VALIDATOR_SET_SIZE_MAX: usize = 128;
            let _ = inputs::generate_step_inputs::<VALIDATOR_SET_SIZE_MAX>(block);
        }
    }
}
