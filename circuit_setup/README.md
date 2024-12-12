
# Crescent Setup

The setup part of the project is built with a few main dependencies

- [Circom](https://github.com/iden3/circom) used as a front end to describe circuits,
- [Circomlib](https://github.com/iden3/circomlib) provides gadgets

and we acknowledge Circom circuits we used from

- [Zkemail](https://github.com/zkemail/zk-email-verify/tree/main)

## Installing Dependencies

Tested under Ubutnu Linux and Ubuntu in the WSL.

1. Install required packages

```bash
sudo apt update
sudo apt install python3-pip nodejs
```

2. Install Rust if not present (not included by default on WSL Ubuntu)

```bash
curl --proto '=https' --tlsv1.3 -sSf https://sh.rustup.rs | sh
```

3. Install required Python modules

```bash
pip install python_jwt
```

4. Install [Circom](https://github.com/iden3/circom)

```bash
git clone https://github.com/iden3/circom.git
cd circom
git checkout v2.1.6
cargo build --release
cargo install --path circom
# After installing Circom remember to add it to your path.
# Either run the following, or add it to your .bashrc
export PATH=$PATH:~/.cargo/bin
```

5. [Circomlib](https://github.com/iden3/circomlib) is included as a git submodule that must be initialized.
Either clone this repo with the option `--recurse-submodules`, or for existing repositories

```bash
git submodule update --init --recursive
```

6. For mDL credentials, the [pyMDOC-CBOR](https://github.com/IdentityPython/pyMDOC-CBOR) Python module must be installed, with the command

```bash
# Linux
pip install git+https://github.com/peppelinux/pyMDOC-CBOR.git
```

```bash
# Windows
# pyMDL-MDOC has a bug in the setup we need to fix for proper installation on Windows
git clone https://github.com/peppelinux/pyMDL-MDOC.git
cd pyMDL-MDOC
sed -i "s|i.replace(f'{_pkg_name}/', '')|i.replace(f'{_pkg_name}\\\\\\\\', '')|g" setup.py
pip install .
```

## Sample JWT and mDL

To work with Crescent, the prover and verifier both need the issuer's public key, and the prover needs a JWT.
The setup script will generate a sample JWT in `inputs/rs256`.

```bash
    inputs/rs256/token.jwt
    inputs/rs256/issuer.pub
```

We provide a sample mDL credential in `/inputs/mdl1/`.

## Running Setup

We describe how to run setup for the sample token provided in `inputs/rs256/`.  This is a JWT, with similar claims to those issued by Microsoft Entra for enterprise users, but created with a freshly generated keypair.
All of the artifacts created by Crescent for the instance `rs256` will be written to `generated_files/rs256/`.

The file `inputs/rs256/config.json` contains a "proof specification", some basic information necessary to create the proof, such as the token length and which claims are to be revealed.
To run setup, change to the `scripts` directory and run the command

```bash
./run_setup.sh rs256
```

Setup runs Circom and creates the R1CS instance to verify the JWT and reveal some of the outputs, as well
as the setup steps of the ZK proof system to get the prover and verifier parameters (output as files in `generated_files/rs256`).
Overall this is slow, but only needs to be run once for a given token issuer and proof specification.

Once this script completes, all files required for showing and verifying proofs will have copied to `creds/test-vectors/rs256`.

# Troubleshooting

For some large circuits, Circom may use a large amount of RAM and be killed.
If the log output during Circom compilation stops abruptly, check towards the end of `/var/log/kern.log`
for an entry like

```bash
Oct  9 16:09:18 computer-name kernel: [22997.693985] Out of memory: Killed process 13747 (circom) total-vm:31880260kB, anon-rss:30334800kB, file-rss:0kB, shmem-rss:0kB, UID:1000 pgtables:62048kB oom_score_adj:0
```
