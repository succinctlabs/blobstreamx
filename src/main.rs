use celestia::{
    fixture::{
        create_block_fixture, create_data_commitment_fixture, create_header_chain_fixture,
        generate_val_array,
    },
    inputs::generate_step_inputs,
};
use clap::Parser;

#[derive(Parser, Debug)]
enum Function {
    /// Calls the generate_val_array function
    GenerateValArray {
        /// Number of validators to generate test cases for
        #[clap(short, long)]
        validators: usize,
    },
    /// Calls the create_block_fixture function
    CreateBlockFixture {
        /// The block number to create a new fixture for
        #[clap(short, long)]
        block: usize,
    },
    /// Calls the create_data_commitment_fixture function
    CreateDataCommitmentFixture {
        /// The block number range to create a new fixture for
        #[clap(short, long)]
        start_block: usize,
        #[clap(short, long)]
        end_block: usize,
    },
    /// Calls the create_header_chain_fixture function
    CreateHeaderChainFixture {
        /// The block number range to create a new fixture for
        #[clap(short, long)]
        trusted_block: usize,
        #[clap(short, long)]
        current_block: usize,
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
            generate_val_array(validators);
        }
        Function::CreateBlockFixture { block } => {
            create_block_fixture(block)
                .await
                .expect("Failed to create new block fixture");
        }
        Function::CreateDataCommitmentFixture {
            start_block,
            end_block,
        } => {
            create_data_commitment_fixture(start_block, end_block)
                .await
                .expect("Failed to create new data commitment fixture");
        }
        Function::CreateHeaderChainFixture {
            trusted_block,
            current_block,
        } => {
            create_header_chain_fixture(trusted_block, current_block)
                .await
                .expect("Failed to create new header chain fixture");
        }
        Function::GenerateStepInputs { block } => {
            const VALIDATOR_SET_SIZE_MAX: usize = 128;
            let _ = generate_step_inputs::<VALIDATOR_SET_SIZE_MAX>(block);
        }
    }
}
