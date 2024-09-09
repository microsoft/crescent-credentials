
# Crescent Setup


The Setup part of the project is built with a few main dependencies

- [Circom](https://github.com/iden3/circom) used as a front end to describe circuits,
- [Circomlib](https://github.com/iden3/circomlib) We use some of the gadgets from Circomlib


and we acknowledge code we used from these projects 
- [Nozee (zkemail for JWT)](https://github.com/sehyunc/nozee) 


## Installing Dependencies
Tested under Ubutnu Linux and Ubuntu in the WSL.

1. Install required packages (pip, cmake, )
```
sudo apt update
sudo apt install python3-pip nodejs
```

2. Install Rust if not present (not included by default on WSL Ubuntu)
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

3. Install required Python modules
```
pip install python_jwt
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


## Sample JWT
To work with Crescent, the prover and verifier both need the issuer's public key, and the prover needs a JWT. 
We provide sample files in `inputs/rs256`.
```
    inputs/rs256/token.jwt
    inputs/rs256/issuer.pub
```

## Running Setup
We describe how to run setup for the sample token provided in `inputs/rs256/`.  This is a JWT, with similar claims to those issued by Microsoft Entra for enterprise users, but created with the sample keypair `inputs/rs256/issuer.prv`, `inputs/rs256/issuer.pub`.
All of the artifacts created by Crescent for the instance  `rs256` will be written to `generated_files/rs256/`. 

The *proof specification* (a description of what to prove) is in the file `inputs/rs256/config.json`, 
this is considered public information, and always present.  
Basically this file lists which claims are revealed, or have a predicate applied to them.

Before running the scripts for setup/prover/verifier, it's handy to watch the log file that will get created:
```
tail -f --follow=name --retry generated_files/rs256/rs256.log
```

During setup, the directory `rs256` must contain three files: `config.json`, `token.jwt`, and `issuer.pub`. 
At this point, `token.jwt` would be a "sample" token created by the issuer, i.e., it must have the same schema as tokens that will
be used later by provers.  Setup uses the token to check that the proof specification is applicable.  
To run setup, change to the `scripts` directory, run the command
```
./run_setup.sh rs256
```
Setup runs Circom and creates the R1CS instance to verify the JWT and prove the predicates from the proof spec, as well
as the setup steps of the ZK proof system to get the prover and verifier parameters (output as files in `generated_files/rs256`). 
Overall this is the slowest part, but need only be run once for a given token issuer and proof specification. 
(TODO: we don't actually call the right ZK setup yet)

# *
# TODO: Documentation below is out-of-date
# *


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


