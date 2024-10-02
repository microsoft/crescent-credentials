# Crescent

Crescent is a library to generate proofs of possession of JWT (JSON Web Tokens) credentials. 
By creating a proof for a JWT, rather than sending it directly, the credential holder may choose
to keep some of the claims in the token private, while still providing the verifier with assurance
that the revealed claims are correct.

This repository contains the Crescent library and a sample application consisting of a JWT issuer,
a browser extension client, and a web server verifier.

## Setup and demo cheat sheet
Once the dev dependencies are installed, to run the end-to-end demo use these commands.
From the root of the git repo
```
cd setup/scripts
./run_setup.sh rs256
cd ../../creds
cargo run --release --features print-trace --example demo rs256 -- --nocapture
```

# Setting up

To setup the library, see the instructions in [`/setup/README.md`](./setup/README.md);
to setup the sample application, see [`sample/README.md`](./sample/README.md).

## Running the example

Once setup is done, to run the main example, from `creds`:
```
cargo run --release --features print-trace --example demo rs256 -- --nocapture
```

# Running the demo steps separately 
There is a command line tool that can be used to run the individual parts of the demo separately.  This clearly separates the roles of prover and verifier, and shows what parameters are required by each.    The filesystem is used to store data between steps, and also to "communicate" show proofs from prover to verifier. 

The steps are
* `zksetup` Generates the (circuit-specific) system parameters 
* `prove` Generates the Groth16 proof for a credential.  Stored for future presentation proofs in the "client state"
* `show` Creates a fresh and unlinkable presentation proof to be sent to the verifier
* `verify` Checks that the show proof is valid

After the circuit is setup and the data copied into, e.g., `test-vectors/rs256`, we can run each of the demo steps as follows.

```
cargo run --bin crescent --release --features print-trace zksetup --name rs256
cargo run --bin crescent --release --features print-trace prove --name rs256
cargo run --bin crescent --release --features print-trace show --name rs256
cargo run --bin crescent --release --features print-trace verify --name rs256
```

Note that the steps have to be run in order, but once the client state is created by `prove`, the `show` and `verify` steps can be run repeatedly.

# Project

> This repo has been populated by an initial template to help get you started. Please
> make sure to update the content to build a great experience for community-building.

As the maintainer of this project, please make a few updates:

- Improving this README.MD file to provide a great experience
- Updating SUPPORT.MD with content about this project's support experience
- Understanding the security reporting process in SECURITY.MD
- Remove this section from the README

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

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
