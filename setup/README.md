
# Crescent: A library for adding privacy to existing credentials

Crescent is a library to generate proofs of possession of JWT (JSON web tokens) credentials. 
By creating a proof for a JWT, rather than sending it directly, the credential holder may choose
to keep some of the claims in the token private, while still providing the verifier with assurance
that the revealed claims are as correct (as they were issued).

The project is built with a few main dependencies

- [Circom](https://github.com/iden3/circom) used as a front end to describe circuits,
- [Circomlib](https://github.com/iden3/circomlib) We use some of the gadgets from Circomlib
- [Spartan2](https://github.com/microsoft/spartan2) a new implementation of [Spartan](https://ia.cr/2019/550) with support for bellperson circuits and the Hyrax polynomial commitment scheme

and we acknowledge code we used from these projects 
- [Nozee (zkemail for JWT)](https://github.com/sehyunc/nozee) 
We use some of the Circom code from this project 
- [Nova-Scotia](https://github.com/nalinbhardwaj/Nova-Scotia)
We took a subset of the code in this project to read Circom generated R1CS instances and witness generators and create a [bellperson](https://github.com/filecoin-project/bellperson) 
circuit that we can pass to [Spartan2](https://github.com/Microsoft/Spartan2/).

## Installing Dependencies
Tested under Ubutnu Linux and Ubuntu in the WSL.

1. Install required packages (pip, cmake, )
```
sudo apt update
sudo apt install python3-pip libgmp-dev nasm nodejs
sudo apt remove cmake  # Remove existing version
sudo pip install cmake --upgrade
```

2. Install Rust if not present (not included by default on WSL Ubuntu)
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

3. Install required Python modules
```
pip install requests msal python_jwt
```

4. Install json. (This is required by Circom's C++ witness generator; inputs are provided as JSON)
```
# json
git clone https://github.com/nlohmann/json.git
cd json
git checkout v3.11.2
mkdir build
cd build
cmake ..
cmake --build .
sudo cmake --install .
```

5. Install [Circom](https://github.com/iden3/circom) (we need a version supporting the [pasta curves](https://github.com/zcash/pasta_curves)).

```
git clone https://github.com/iden3/circom.git
cd circom
git checkout v2.1.6
cargo build --release
cargo install --path circom
# After installing Circom remember to add it to your path.
# Either run the following, or add it to your .bashrc
export PATH=$PATH:~/.cargo/bin
```

6. [Circomlib](https://github.com/iden3/circomlib) is included as a git submodule that must be initialized. 
Either clone this repo with the option `--recurse-submodules`, or for existing repositories
```
git submodule update --init --recursive
```


## Get a JWT (optional)
To work with Crescent, the prover and verifier both need the issuer's public key, and the prover needs a JWT. 
We provide sample files in `inputs/demo`.
```
    inputs/demo/token.jwt
    inputs/demo/issuer.pub
```

<b> TODO: generate new samples rather than use AAD ones </b>

### Microsoft-internal *(TODO: Remove before release)*
To get a token run the python script in `creds/ms-identity-python-devicecodeflow`:
```
python3 ./device_flow_sample.py
```
and follow the instructions, it will provide a URL and a code to enter. 
(This is a modified version of the [sample provided by Microsoft Identity](https://github.com/Azure-Samples/ms-identity-python-devicecodeflow).)
By default it will cache tokens, so you may have to delete the file `creds/ms-identity-python-devicecodeflow/token_cache.bin` in order to get a fresh token. 

To look at a JWT, you can copy and paste it into `https://jwt.ms` and it will be parsed in your browser.  The python script above will also parse and dump the credential information (as will our prover setup script).

<i>As of 8/15/2023 we have been testing only with AAD tokens, and have not tested MSA tokens in a month or so.
Everything should work with MSAs but this needs to be tested</i>

## Creating and verifying proofs
There are three steps that must be run in order: Setup, Prove and Verify. 
To get started, create a directory `inputs/my_proof` where we'll store information related to the proof being created.
A sample directory `inputs/demo` is also provided (replace `my_proof` with `demo` in the following instructions to run the demo).
All of the artifacts created by Crescent for your configuration `my_proof` will be written to `generated_files/my_proof/`. 

The *proof specification* (a description of what to prove) is in the file `inputs/my_proof/config.json`, 
this is considered public information, and always present.  There is an example proof specification in `inputs/demo/config.json`.
Basically this file lists which claims are revealed, or have a predicate applied to them.

Before running the scripts for setup/prover/verifier, it's handy to watch the log file that will get created:
```
tail -f --follow=name --retry generated_files/my_proof/my_proof.log
```

### Running Setup
During setup, the directory `my_proof` must contain three files: `config.json`, `token.jwt`, and `issuer.pub`. 
At this point, `token.jwt` must be a "sample" token created by the issuer, i.e., it must have the same schema as tokens that will
be used later by provers.  Setup uses the token to check that the proof specification is applicable.  
To run setup, from the `scripts` directory, run the command
```
./run_setup my_proof
```
to run your new proof as specified in `inputs/my_proof` (or `./run_setup demo` to run the demo).
Setup runs Circom and creates the R1CS instance to verify the JWT and prove the predicates from the proof spec, as well
as run's Spartan2's setup to get the prover and verifier paramters (output as files in `generated_files/my_proof`). 
Overall this is the slowest part, but need only be run once for a given token issuer and proof specification. 

### Running the Prover
During proof generation, all three files must also be present, and the `token.jwt` file must be the prover's credential. 
It may be necessary to update `config.json` when generating the proof, if some of the predicates require input values. 
For example, in `demo`, with a fresh JWT, you first have to update the timestamp in `config.json` to be the current time (or near it). 
The line
```
"special_inputs": {"current_ts": "1685752974"}
```
has a unix timstamp.  To create one for the current time, you can use the command:
```
date +%s
```
and to get the date back from a timestamp, use
```
date -d @1685752974
Fri Jun  2 17:42:54 PDT 2023
```

To run the prover, from the `scripts` directory, run the command
```
./run_prover my_proof
```
The proof is written to `generated_files/my_proof/proof.bin` and the inputs used by the prover are in `generated_files/my_proof/prover_inputs.json`.

### Running the Verifier
The verifier does not use `token.jwt` (obviously!) and expects to find `proof.bin` in `generated_files/my_proof` along with the verifier parameters created during Setup.

To run the verifier, from the `scripts` directory, run the command
```
./run_verifier my_proof
```
The verifier script prints out whether the proof was successfully verified, whether the outputs of the circuit were correct, and prints out any revealed claims. 


## Rust command-line program and API
The scripts described above prepare inputs and call a Rust binary called `crescent` that implements the setup, prover and verifier steps. Other applications may wish to 
use this Rust program directly, or call the Rust APIs behind it. See `src/main.rs` and `src/lib.rs`. 


# Misc Notes
For some large circuits, Circom may use more than 32GB of RAM which (on my system) will cause it to be killed. 
If the log output during Circom compilation stops abrubptly, check towards the end of `/var/log/kern.log`
for an entry like 
```
Oct  9 16:09:18 gregz-linux kernel: [22997.693985] Out of memory: Killed process 13747 (circom) total-vm:31880260kB, anon-rss:30334800kB, file-rss:0kB, shmem-rss:0kB, UID:1000 pgtables:62048kB oom_score_adj:0
```


