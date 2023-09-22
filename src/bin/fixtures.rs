use celestia::fixture::{create_block_fixture, create_data_commitment_fixture, generate_val_array};
use celestia::inputs::generate_step_inputs;
use clap::Parser;

#[derive(Parser, Debug)]
enum Function {
    GenerateValArray {
        /// Number of validators to generate test cases for.
        #[clap(short, long)]
        validators: usize,
    },
    CreateBlockFixture {
        /// The block number to create a new fixture for.
        #[clap(short, long)]
        block: usize,
    },
    CreateDataCommitmentFixture {
        /// The start block number to create a new fixture for.
        #[clap(short, long)]
        start_block: usize,

        /// The end block number to create a new fixture for.
        #[clap(short, long)]
        end_block: usize,
    },
    GenerateStepInputs {
        /// Number of validators to generate test cases for.
        #[clap(short, long)]
        block: usize,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
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
        Function::GenerateStepInputs { block } => {
            const VALIDATOR_SET_SIZE_MAX: usize = 128;
            let _ = generate_step_inputs::<VALIDATOR_SET_SIZE_MAX>(block);
        }
    }
}
