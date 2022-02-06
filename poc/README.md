# Extended OPAQUE Proof-of-Concept

To get to grips with hash-to-curve algorithms, I look at a use of them - OPAQUE. To really see how the protocol flow works, I extend the existing proof-of-concept created by the CFRG of the IRTF and write a client and server so we can see it in action.

## Links

- [Original OPAQUE Proof-of-Concept](https://github.com/cfrg/draft-irtf-cfrg-opaque/tree/master/poc)
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

1. Decide on the socket for the server (IP address and port number) and change this at the top of `server.sage`. If client and server are on the same device then leave as the default which uses `localhost:1337`
1. Run `make runserver` on the device acting as the server
1. Run the client on the device acting as the client:
    - For a command-line client, run `make runclient` and you will be prompted in the terminal to register or login and enter your credentials
    - For a web client, run `make runwebclient` and you will be prompted in the terminal what the URL is. This can be changed at the top of `web.sage`

## Configuration

The following configurations can easily be changed:

- **Communicating Socket**: The socket that the server listens on can be changed by changing the `SOCKET` constant at the top of `server.sage`. By default, it is `localhost:1337`
- **Web Socket**: The socket that the web client runs on (which must be different to the communicating socket) can be changed by editing the `WEB_SOCKET` constant at the top of `web.sage`. By default, it is `localhost:8080`
- **Logging**: `client.sage`, `server.sage` and `web.sage` define their own logging configurations. The command-line client and server define them at the top of their `main` methods and log to stderr, whereas the web client defines it at the top of the file and logs to both stderr and a log file. The web client reads this log file to displays the messages send/received and keys derived on the web page.
- **OPAQUE Configuration**: The cryptographic configuration that OPAQUE uses can be changed by editing the `CONFIG` constant at the top of `server.sage`. By default, it is the same default as defined by the CFRG in their test file. It must be an instance of `Configuration` which is defined in `opaque_ake.sage`. This configuration consists of the following and is detailed in section 7 of the draft:
    - OPRF suite (Oblivious Pseudo-Random Function) - the topic of VOPRF (see links). For example OPRF(ristretto255, SHA-512) and OPRF(P-256, SHA-256)
    - KDF (Key Derivation Function): Can be an instance of `HKDF` from `opaque_core.sage` created from SHA-512 or SHA-256
    - MAC (Message Authentication Code): Can be an instance of `HMAC` from `opaque_core.sage` created from SHA-512 or SHA-256
    - Hash - like SHA-256 or SHA-512
    - MHF (Message Hardening Function) - can be Argon2, scrypt or PBKDF2 but must have fixed parameter choices. An instance of `MHF` in `opaque_core.sage`
    - Group - the topic of Hash-to-Curve (see links) - should match that of OPRF, such as ristretto255 or P-256. An instance of a subclass of `Group` such as `GroupP256` or `GroupRistretto255` in `groups.sage` (from OPRF code, imports Hash-to-Curve code)
    - Context - byte string representing application specific information or configuration parameters needed to prevent cross-protocol or downgrade attacks