pub mod merkle;
pub mod scripts;
pub mod u32;
pub mod utils;
pub mod validator;

use crate::scripts::generate_tests;

use clap::{Arg, ArgAction, Command, Parser};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of validators to generate test cases for
    #[arg(short, long)]
    validators: usize,
}

fn main() {
    let args = Args::parse();

    println!("Number of validators: {}", args.validators);
    generate_tests::generate_tendermint_test_cases(args.validators);
}
