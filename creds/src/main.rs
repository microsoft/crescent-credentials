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
        Command::Prove {
            input,
            r1cs,
            pk,
            witness_generator,
            proof,
        } => {
            let input_file = root.join(input);
            let r1cs_file = root.join(r1cs);
            let pk_file = root.join(pk);
            let witness_generator_file = root.join(witness_generator);
            let proof_file = root.join(proof);
            run_prover(
                input_file,
                r1cs_file,
                pk_file,
                witness_generator_file,
                proof_file,
            );
        }
        Command::Show {
            input,
            r1cs,
            pk,
            witness_generator,
            proof,
        } => {
            let input_file = root.join(input);
            let r1cs_file = root.join(r1cs);
            let pk_file = root.join(pk);
            let witness_generator_file = root.join(witness_generator);
            let proof_file = root.join(proof);
            run_show(
                input_file,
                r1cs_file,
                pk_file,
                witness_generator_file,
                proof_file,
            );
        }        
        Command::Verify { input, vk, proof } => {
            let input_file = root.join(input);
            let vk_file = root.join(vk);
            let proof_file = root.join(proof);
            run_verifier(
                input_file,
                vk_file,
                proof_file,
            );
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

        // #[structopt(long)]
        // pk: String,

        // #[structopt(long)]
        // vk: String,
    },

    #[structopt(about = "Run prover.")]
    Prove {
        #[structopt(long)]
        input: String,

        #[structopt(long)]
        r1cs: String,

        #[structopt(long)]
        pk: String,

        #[structopt(long)]
        witness_generator: String,

        #[structopt(long)]
        proof: String,
    },

    #[structopt(about = "Generate a presentation proof to Show a credential.")]
    Show {
        #[structopt(long)]
        input: String,

        #[structopt(long)]
        r1cs: String,

        #[structopt(long)]
        pk: String,

        #[structopt(long)]
        witness_generator: String,

        #[structopt(long)]
        proof: String,
    },    

    #[structopt(about = "Verifier a presentation proof.")]
    Verify {
        #[structopt(long)]
        input: String,

        #[structopt(long)]
        vk: String,

        #[structopt(long)]
        proof: String,
    },
}
