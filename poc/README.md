# Extended OPAQUE Proof-of-Concept

This extension of the CFRG reference OPAQUE proof-of-concept adds a client and server to clearly show the inputs the client and server need, the outputs they produce and the steps they need to take in the OPAQUE protocol.

In `client.sage` and `server.sage`, there are functions for registration, login without AKE (Authenticated Key Exchange) and login with AKE. These aim to show, as clearly as possible, what the client and server do at each stage including sending messages, receiving messages and doing computation. The CFRG proof-of-concept already has functions for the computations required which this extension makes use of. Their inner workings are explained in detail in the OPAQUE specification.

Other functions in `client.sage` and `server.sage` facilitate the connection between client and server using sockets, and determine which mode to use (registration, login without AKE or login with AKE). However some parts are important for the core OPAQUE protocol, for example, in the `main` method in `server.sage`, the server generates a keypair and OPRF seed which are required inputs to the core functions.

We also show how to prevent client enumeration (at least for login) by creating a fake record that is used if a login is attempted with an unregistered username.

We log many things, including messages sent/received and keys derived, to clearly demonstrate how the OPAQUE protocol works in action.

`web.sage` is a web interface for the client to replace the command-line interface in `client.sage`. It calls the core functions in `client.sage` for the back-end. In addition to being more user-friendly than the command-line interface, this formats messages and keys clearly so it's easy to see what's happening.

`test_flow.sage` tests the client and server code by acting as a client and performing several requests to the server (which must be running before running this test). It tries things such as logging in with an unregistered username.

## Links

- [Reference OPAQUE Proof-of-Concept](https://github.com/cfrg/draft-irtf-cfrg-opaque/tree/master/poc)
- [This Extended OPAQUE Proof-of-Concept](https://github.com/jamesw1892/OPAQUE/tree/master/poc)
- [OPAQUE Specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/) which explains how the protocol works
- Related documents to OPAQUE:
    - VOPRF:
        - [Specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-voprf/)
        - [Reference Proof-of-Concept](https://github.com/cfrg/draft-irtf-cfrg-voprf/tree/master/poc)
    - Hash-To-Curve:
        - [Specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
        - [Reference Proof-of-Concept](https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/tree/master/poc)

## Usage

Before first use, download the submodules and run `make setup` to copy necessary files from them into this directory.

1. Decide on the socket for the server (IP address and port number) and change this at the top of `server.sage`. If client and server are on the same device then leave as the default which uses `localhost:1337`
1. Run `make runserver` on the device acting as the server
1. Run the client on the device acting as the client:
    - For a command-line client, run `make runclient` and you will be prompted in the terminal to register or login and enter your credentials
    - For a web client, run `make runwebclient` and you will be prompted in the terminal what the URL is. This can be changed at the top of `web.sage`
    - To test the extension, run `make testflow`

## Configuration

The following configurations can easily be changed:

- **Communicating Socket**: The socket that the server listens on can be changed by changing the `SOCKET` constant at the top of `server.sage`. By default, it is `localhost:1337`
- **Web Socket**: The socket that the web client runs on (which must be different to the communicating socket) can be changed by editing the `WEB_SOCKET` constant at the top of `web.sage`. By default, it is `localhost:8080`
- **Logging**: `client.sage`, `server.sage` and `web.sage` define their own logging configurations. The command-line client and server define them at the top of their `main` methods and log to stderr, whereas the web client defines it at the top of the file and logs to both stderr and a log file. The web client reads this log file to display the messages send/received and keys derived on the web page.
- **OPAQUE Configuration**: The cryptographic configuration that OPAQUE uses can be changed by editing the `CONFIG` constant at the top of `server.sage`. By default, it is the same default as defined by the CFRG in their test file. It must be an instance of `Configuration` which is defined in `opaque_ake.sage`. This configuration consists of the following and is detailed in section 7 of the draft:
    - OPRF suite (Oblivious Pseudo-Random Function) - the topic of VOPRF (see links). For example OPRF(ristretto255, SHA-512) and OPRF(P-256, SHA-256)
    - KDF (Key Derivation Function): Can be an instance of `HKDF` from `opaque_core.sage` created from SHA-512 or SHA-256
    - MAC (Message Authentication Code): Can be an instance of `HMAC` from `opaque_core.sage` created from SHA-512 or SHA-256
    - Hash - like SHA-256 or SHA-512
    - KSF (Key Stretching Function) - can be Argon2, scrypt or PBKDF2 but must have fixed parameter choices. An instance of `KeyStretchingFunction` in `opaque_core.sage`
    - Group - the topic of Hash-to-Curve (see links) - should match that of OPRF, such as ristretto255 or P-256. An instance of a subclass of `Group` such as `GroupP256` or `GroupRistretto255` in `groups.sage` (from OPRF code, imports Hash-to-Curve code)
    - Context - byte string representing application specific information or configuration parameters needed to prevent cross-protocol or downgrade attacks