# Crescent

_version 0.5_

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

Also check out the [blog post](https://christianpaquin.github.io/2024-12-19-crescent-creds.html)
for an overview, a decription and video of the samples.

## Setting up

To setup the library, see the instructions in [`/circuit_setup/README.md`](./circuit_setup/README.md);
to setup the sample application, see [`sample/README.md`](./sample/README.md).

To check that the library has been setup correctly, run

```bash
cd creds
cargo test --release
```

## Running the demo steps from the command line

There is a command line tool that can be used to run the individual parts of the demo separately.  This clearly separates the roles of prover and verifier, and shows what parameters are required by each.  The filesystem is used to store data between steps, and also to "communicate" show proofs from prover to verifier.

The circuit setup must be completed first, by running

```bash
cd circuit_setup/scripts
./run_setup.sh <param>
cd ../../creds
```

Where `<param>` is one of the supported parameter sets:
* `rs256`: for a RSA-SHA256 signed JWT credential, hardcoding the disclosure of the user's email domain,
* `rs256-sd`: for a RSA-SHA256 signed JWT credential, supporting selective disclosure of its attributes,
* `rs256-db`: for a device-bound RSA-SHA256 signed JWT credential, supporting selective disclosure of its attributes,
* `mdl1`: for a device-bound ECSDA mDL credential, supporting selective disclosure of its attributes

Circuit setup will copy data (parameters etc.) into `creds/test-vectors/`.

The individual steps are

* `zksetup` Generates the (circuit-specific) system parameters
* `prove` Generates the Groth16 proof for a credential.  Stored for future presentation proofs in the "client state"
* `show` Creates a fresh and unlinkable presentation proof to be sent to the verifier
* `verify` Checks that the show proof is valid

and we can run each step as follows

```bash
cargo run --bin crescent --release --features print-trace zksetup --name <param>
cargo run --bin crescent --release --features print-trace prove --name <param>
cargo run --bin crescent --release --features print-trace show --name <param> [--presentation-message "..."]
cargo run --bin crescent --release --features print-trace verify --name <param> [--presentation-message "..."]
```

The `--name` parameter must be one of the `<param>` option above. An optional text presentation message can be passed to the `show` and `prove` steps to bind the presentation to some application data (e.g., a verifier challenge, some data to sign, etc.).

Note that the steps have to be run in order, but once the client state is created by `prove`, the `show` and `verify` steps can be run repeatedly.

### Selective Disclosure
The `rs256` parameter set always discloses the domain of the email address to the verifier. 

The `rs256-sd`, `rs256-db`, and `mdl1` parameter sets demonstrate how to disclose a subset of the attributes in a credential. For example, 
the file `creds/test-vectors/rs256-sd/proof_spec.json` contains 
```
{
    "revealed" : ["family_name", "tenant_ctry", "auth_time", "aud"]
}
```
which means that the proof will disclose those attributes to the verifier.  The subset of the attributes that may be revealed in this way is limited to those in `circuit_setup/inputs/rs256-sd/config.json` that have the `reveal` or `reveal_digest` boolean set to `true`. 
The `reveal_digest` option is used for values that may be larger than 31 bytes; they will get hashed first.  Setting this flag changes how the circuit setup phase handles those attributes, allowing them to be optionally revealed during `show`.

To experiment with selective disclosure, try removing `aud` from the list of revealed attributes, or adding `given_name` to the list of revealed attributes in the proof specification file.

### Range proofs

Crescent proves for all parameter set that the credential is not expired by creating a range proof that the expiration date (the `exp` claim for JWTs, the `valid_until` one for mDL) is later than the current time.

The `mdl1` parameter set also supports proving that an attribute is `X years old`. For example, the file `` contains:
```
{
    "range_over_year": {"birth_date": 18}
}
```
which means that the proof will create a range prove to show that the encoded `birth_date` is such that the user is at least 18 of age.

### Device-Bound Credentials
The `rs256-db` and `mdl1` parameter sets demonstrate a credential that is *device bound*.  This means that the JWT or mDL encodes the public key of an ECDSA signing key, where the private key is stored by a device (such as a hardware security module), and the device exposes only a signing API. 
When the credential is used, the verifier expects the holder to demonstrate possession of the device key, by signing a challenge.  During circuit setup, the file `circuit_setup/inputs/rs256-db/config.json`, for example, has the line `"device_bound": true`, which indicates the sample credential should be generated with a device key.  In the demo, a fresh ECDSA key pair is generated in software, no special hardware is required.
For show proofs, the file `creds/test-vectors/rs256-db/proof_spec.json`, for example, contains 
```
{
    "revealed" : ["family_name", "tenant_ctry", "auth_time", "aud"],
    "device_bound" : true, 
    "presentation_message" : [1, 2, 3, 4]
}
```
which specifies a subset of attributes to disclose, as in the `rs256-sd` example.  The `device-bound` flag is also set here, and the `presentation_message` is a byte string that that encodes a challenge from the verifier. The `presentation_message` is sent to the device, then the show proof creates a proof of knowledge of the device signature (unlinkably). 

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
