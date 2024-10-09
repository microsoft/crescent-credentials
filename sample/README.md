# Crescent Sample

This folder contains a sample issuer, client, and verifier making use of the Crescent system. Note that these
+components are for demonstration only; they should not be used in production environments.

* Issuer: a nginx server that issues JWT tokens; see [`issuer/README.md`](./issuer/README.md)
* Client: a browser extension that stores JWT tokens and presents ZK proofs [`client/README.md`](./client/README.md)
* Verifier: a web application that verifies ZK proofs [`verifier/README.md`](./verifier/README.md)
