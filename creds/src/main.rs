// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crescent::{run_zksetup, run_prover, run_show, run_verifier};
use std::env::current_dir;

use structopt::StructOpt;

fn main() {
    let root = current_dir().unwrap();
    let opt = Opt::from_args();

    match opt.cmd {
        Command::Zksetup{ name } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            let ret = run_zksetup(base_path);
            if ret == 0 {
                return ();
            }
        }
        Command::Prove { name } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            run_prover(base_path);
        }
        Command::Show { name } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            run_show(base_path);
        }        
        Command::Verify { name } => {
            let name_path = format!("test-vectors/{}", name);
            let base_path = root.join(name_path);
            run_verifier(base_path);
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "Credential selective disclosure application", about = "Selectively reveal claims or prove predicates for a credential.")]
pub struct Opt {
    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(Debug, StructOpt)]
pub enum Command {
    #[structopt(about = "Setup parameters for the ZK proof systems (public params for the Groth16 and Show proofs).")]
    Zksetup {
        #[structopt(long)]
        name: String,
    },

    #[structopt(about = "Run prover.")]
    Prove {
        #[structopt(long)]
        name: String,
    },

    #[structopt(about = "Generate a presentation proof to Show a credential.")]
    Show {
        #[structopt(long)]
        name: String,
    },    

    #[structopt(about = "Verifier a presentation proof.")]
    Verify {
        #[structopt(long)]
        name: String,
    },
}
