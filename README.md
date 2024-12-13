# Crescent

_version 0.4_

Crescent is a library to generate proofs of possession of JSON Web Tokens (JWT) and
mobile Driver's Licenses (mDL) credentials.
By creating a proof for a JWT or mDL, rather than sending it directly, the credential holder may choose
to keep some of the claims in the credential private, while still providing the verifier with assurance
that the revealed claims are correct and that the underlying credential is still valid.

This repository contains the Crescent library and a sample application consisting of a JWT issuer,
a setup service, a browser extension client and client helper service, and a web server verifier. some
external dependencies have been forked into this project; see the [NOTICE](./NOTICE.md) file for details

*Disclaimer: This code has not been carefully audited for security and should not be used in a production environment.*

## Documentation
A report describing Crescent is available on the IACR ePrint Archive. 

[Crescent: Stronger Privacy for Existing Credentials (DRAFT)](https://eprint.iacr.org/2024/2013)   
Christian Paquin, Guru-Vamsi Policharla and Greg Zaverucha   
December 2024  

## Setting up

To setup the library, see the instructions in [`/circuit_setup/README.md`](./circuit_setup/README.md);
to setup the sample application, see [`sample/README.md`](./sample/README.md).

To check that the library has been setup correctly, run

```bash
cd creds
cargo test --release
```

### Enabling symlinks with git on Windows

This project uses symlinks to share directories within the project. On Windows, symlinks require administrator privileges. Git can be configured to create project symlinks when cloning the repository.
To enable symlinks with git, run the following command:

```bash
git config --global core.symlinks true
```

If you have already cloned the repository, you can delete and re-clone the repository for the symlinks to be created or manually create the link by running the following CMD command in the project root directory:

```cmd
mklink /J circuit_setup\circuits-mdl\circomlib circuit_setup\circuits\circomlib
```

Verify `circuit_setup\circuits-mdl\circomlib` is now a directory.

## Running the demo steps from the command line

There is a command line tool that can be used to run the individual parts of the demo separately.  This clearly separates the roles of prover and verifier, and shows what parameters are required by each.  The filesystem is used to store data between steps, and also to "communicate" show proofs from prover to verifier.

The circuit setup must be completed first, by running

```bash
cd circuit_setup/scripts
./run_setup.sh rs256
./run_setup.sh mdl1
cd ../../creds
```

Circuit setup will copy data (parameters etc.) into `creds/test-vectors/`.

The individual steps are

* `zksetup` Generates the (circuit-specific) system parameters
* `prove` Generates the Groth16 proof for a credential.  Stored for future presentation proofs in the "client state"
* `show` Creates a fresh and unlinkable presentation proof to be sent to the verifier
* `verify` Checks that the show proof is valid

and we can run each step as follows

```bash
cargo run --bin crescent --release --features print-trace zksetup --name rs256
cargo run --bin crescent --release --features print-trace prove --name rs256
cargo run --bin crescent --release --features print-trace show --name rs256
cargo run --bin crescent --release --features print-trace verify --name rs256
```

The `--name` parameter, used in circuit setup and with the command-line tool, specifies which credential type is used, the two examples are `rs256`, a JWT signed with RSA256, and `mdl1` a sample mobile driver's license.

Note that the steps have to be run in order, but once the client state is created by `prove`, the `show` and `verify` steps can be run repeatedly.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit <https://cla.opensource.microsoft.com>.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft
trademarks or logos is subject to and must follow
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
