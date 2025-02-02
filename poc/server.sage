"""
Single-threaded server for OPAQUE allowing one client at a time to connect
using a socket and either register a username and password, or login with a
username and password, with or without running the Authenticated Key Exchange
(AKE) flow simultaneously to logging in.
"""

from enum import Enum
import logging
import socket
import sys
from typing import Dict, Union

try:
    from sagelib.opaque_ake import Configuration, OPAQUE3DH, deserialize_tripleDH_init, deserialize_tripleDH_respond, deserialize_tripleDH_finish
    from sagelib.opaque_common import _as_bytes, zero_bytes
    from sagelib.opaque_core import OPAQUECore
    from sagelib.opaque_drng import OPAQUEDRNG
    from sagelib.opaque_messages import deserialize_registration_request, deserialize_registration_upload, deserialize_credential_response, deserialize_credential_request, RegistrationUpload, Envelope
    from sagelib.test_opaque_ake import default_opaque_configuration
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

# use localhost for testing
SOCKET = ("127.0.0.1", 31415)

# configuration to use
CONFIG = default_opaque_configuration

class Mode(Enum):
    """
    Determine what mode of operation to use - registration or login.
    And if login, whether to use an AKE too
    """

    REGISTRATION = "r"
    LOGIN_NO_AKE = "l"
    LOGIN_AKE = "a"

    @staticmethod
    def get(val: str):
        """
        Get the Mode enum with value 'val'.
        Raises ValueError if there is no Mode with the given value.
        """
        for mode in Mode:
            if val == mode.value:
                return mode
        raise ValueError("Invalid mode")

# server's identifier
IDS = _as_bytes("server.com")

# maximum number of bytes to receive through the socket each time
RECV_LEN = 1024

# random number generator
RNG = OPAQUEDRNG(_as_bytes("client server poc extension"))

def formatKE1(config: Configuration, serialized_ke1: bytes) -> str:
    """
    Return a string representation of KE1
    """

    # serialized_ke1 is made up of credential_request and tripleDH_init
    # concatenated together. So deserialize credential_request and get how long
    # it is. Then we know the rest of serialized_ke1 is tripleDH_init which we
    # can deserialize too
    credential_request, offset = deserialize_credential_request(config, serialized_ke1)
    tripleDH_init = deserialize_tripleDH_init(config, serialized_ke1[offset:])

    # return their string representations on different lines
    return str(credential_request) + "\n" + str(tripleDH_init)

def formatKE2(config: Configuration, serialized_ke2: bytes) -> str:
    """
    Return a string representation of KE2
    """

    # serialized_ke2 is made up of credential_response and tripleDH_respond
    # concatenated together. So deserialize credential_response and get how long
    # it is. Then we know the rest of serialized_ke2 is tripleDH_respond which we
    # can deserialize too
    credential_response, offset = deserialize_credential_response(config, serialized_ke2)
    tripleDH_respond = deserialize_tripleDH_respond(config, serialized_ke2[offset:])

    # return their string representations on different lines
    return str(credential_response) + "\n" + str(tripleDH_respond)

def formatKE3(config: Configuration, serialized_ke3: bytes) -> str:
    """
    Return a string representation of KE3
    """

    # serialized_ke3 is only made up of tripleDH_finish so just deserialize it
    tripleDH_finish = deserialize_tripleDH_finish(config, serialized_ke3)

    # return its string representation
    return str(tripleDH_finish)

def server_registration(connection: socket.socket, config: Configuration,
        idU: bytes, oprf_seed: bytes, pkS_bytes: bytes) -> RegistrationUpload:
    """
    Run the server's registration flow to store the client's credentials.

    The server inputs its parameters (config). idU is the client's username
    encoded as bytes that has already been received from the client. pkS_bytes
    is the server's public key encoded as bytes. oprf_seed is the seed for OPRF.
    The output is the record containing the client's credentials which needs to
    be stored.
    """

    logging.info("Starting registration")

    core = OPAQUECore(config, RNG)

    # receive and deserialise the registration request
    serialized_request = connection.recv(RECV_LEN)
    request = deserialize_registration_request(config, serialized_request)
    logging.info(f"Received registration request:\n{request}")

    # create the registration response
    response, _ = core.create_registration_response(request, pkS_bytes, oprf_seed, idU)

    # serialise and send the registration response
    connection.send(response.serialize())
    logging.info(f"Sent registration response:\n{response}")

    # receive and deserialise the record
    serialized_record = connection.recv(RECV_LEN)
    record = deserialize_registration_upload(config, serialized_record)
    logging.info(f"Received record:\n{record}")

    logging.info("Completed registration\n")

    return record

def server_login_no_ake(connection: socket.socket, config: Configuration, idU: bytes,
                 oprf_seed: bytes, pkS_bytes: bytes, record: RegistrationUpload):
    """
    Run the server's login flow without AKE to send the client's credentials to
    them.

    The server inputs its parameters (config) and the record corresponding to
    the client (record) which has already been retrieved based on the username.
    If a username hasn't already been registered then this is a fake record,
    used so the login flow still completes to prevent client enumeration, but
    the client's final step will fail indicating an incorrect username OR password.

    idU is the client's username encoded as bytes that has already been received
    from the client. pkS_bytes is the server's public key encoded as bytes.
    oprf_seed is the seed for OPRF.
    """

    logging.info("Starting login without AKE")

    core = OPAQUECore(config, RNG)

    # receive and deserialise the credential request
    serialized_request = connection.recv(RECV_LEN)
    request, _ = deserialize_credential_request(config, serialized_request)
    logging.info(f"Received credential request:\n{request}")

    # create the credential response
    response = core.create_credential_response(request, pkS_bytes, oprf_seed, record.envU, idU, record.masking_key)

    # serialise and send the credential response
    connection.send(response.serialize())
    logging.info(f"Sent credential response:\n{response}")

    logging.info("Completed login without AKE\n")

def server_login_ake(connection: socket.socket, config: Configuration, idU: bytes,
                     oprf_seed: bytes, record: RegistrationUpload, skS,
                     pkS) -> Union[bytes, None]:
    """
    Run the server's login flow with authenticated key exchange to send the
    client's credentials to them and establish a shared secret session key.

    The server inputs its parameters (config) and the record corresponding to
    the client (record) which has already been retrieved based on the username.
    If a username hasn't already been registered then this is a fake record,
    used so the login flow still completes to prevent client enumeration, but
    the final step will fail and this function returns None, indicating an
    incorrect username OR password.

    idU is the client's username encoded as bytes that has already been received
    from the client. pkS is the server's public key and skS is the server's
    private key, neither are encoded so for example, skS is a scalar and pkS is
    a point on an elliptic curve (the generator * skS). oprf_seed is the seed
    for OPRF.
    """

    logging.info("Starting login with AKE")

    kex = OPAQUE3DH(config, RNG)

    # receive ke1
    serialized_ke1 = connection.recv(RECV_LEN)
    logging.info(f"Received ke1:\n{formatKE1(config, serialized_ke1)}")

    # deserialise the client's public key from the record
    pkU = config.group.deserialize(record.pkU)

    # create ke2
    serialized_ke2 = kex.generate_ke2(serialized_ke1, oprf_seed, idU, record.envU, record.masking_key, IDS, skS, pkS, idU, pkU)

    # send ke2
    connection.send(serialized_ke2)
    logging.info(f"Sent ke2:\n{formatKE2(config, serialized_ke2)}")

    # receive ke3
    serialized_ke3 = connection.recv(RECV_LEN)

    # derive session key
    try:
        session_key = kex.finish(serialized_ke3)
    except:
        logging.warning("Invalid username and/or password\n")
        return None

    logging.info(f"Received ke3:\n{formatKE3(config, serialized_ke3)}")

    logging.info(f"Derived session key:\nSession Key: {session_key.hex()}")

    logging.info("Completed login with AKE\n")

    return session_key

def handle_connection(connection: socket.socket, config: Configuration, oprf_seed: bytes,
                      pkS_bytes: bytes, records: Dict[bytes, RegistrationUpload],
                      skS, pkS, fake_record: RegistrationUpload):
    """
    Handle the given connection to the server - determine what mode is required
    (registration, login without AKE, or login with AKE), then run the server's
    flow for that mode.

    config is the OPRF settings to use. oprf_seed is the seed for OPRF. skS is
    the server's private key and pkS is the server's public key. These are not
    encoded so, for example, skS is a scalar and pkS is a point on an elliptic
    curve (the generator * skS). pkS_bytes is pkS encoded as bytes. records is
    a dictionary mapping from `idU`s (usernames encoded as bytes) to the record
    for that username. fake_record is the record to use if the username is not
    registered to prevent client enumeration during login.
    """

    # the first message is the mode followed by a colon
    # followed by the username
    msg = connection.recv(RECV_LEN).decode().split(":")
    mode = Mode.get(msg[0])
    idU = msg[1].encode() # keep username as bytes

    # for registration:
    if mode is Mode.REGISTRATION:

        # if the username has already been registered then tell the client
        # this will make the next deserialisation step fail and the client
        # should interpret this to mean the username is already registered
        if idU in records:
            connection.send("Username already registered".encode())
            logging.warning("Username already registered\n")

        # otherwise run the main flow and save the record under the username
        else:
            record = server_registration(connection, config, idU, oprf_seed, pkS_bytes)
            records[idU] = record

    # for login (with or without AKE)
    elif mode is Mode.LOGIN_NO_AKE or mode is Mode.LOGIN_AKE:

        # if the username has been registered, use it
        if idU in records:
            record = records[idU]
            logging.info("Record exists")

        # if it hasn't, use a fake record to prevent client enumeration
        else:
            record = fake_record
            logging.info("Record faked")

        # run the relevant flow
        if mode is Mode.LOGIN_NO_AKE:
            server_login_no_ake(connection, config, idU, oprf_seed, pkS_bytes, record)
        else:
            session_key = server_login_ake(connection, config, idU, oprf_seed, record, skS, pkS)

    else:
        logging.error("Invalid mode")

def main(config: Configuration):
    """
    Run the server with given OPRF configuration to respond to client requests
    """

    # logging format - log everything and add 'server' to front of messages
    logging.basicConfig(level=logging.INFO, format="Server %(levelname)s: %(message)s")

    # create a fake record that we can use if the client has not previously registered
    # we still do the login flow to prevent client enumeration. Recommended here:
    # https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html#section-6.3.2.2-4
    random_sk = ZZ(config.group.random_scalar(RNG))
    random_pk = random_sk * config.group.generator()
    serialised_random_pk = config.group.serialize(random_pk)
    empty_envelope = Envelope(zero_bytes(config.Nn), zero_bytes(config.Nm))
    fake_record = RegistrationUpload(serialised_random_pk, RNG.random_bytes(config.Nh), empty_envelope)

    # stores registered credentials where the key is a byte string idU - the
    # client identity which is the same as the credential identifier for us
    # and the value is a `RegistrationUpload` instance
    records = dict()

    # generate server's public and private keypair and OPRF seed
    # these can be kept the same for all clients as stated here:
    # https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html#section-5-1
    # https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html#name-finalize-registration
    skS = ZZ(config.group.random_scalar(RNG))
    pkS = skS * config.group.generator()
    pkS_bytes = config.group.serialize(pkS)
    oprf_seed = RNG.random_bytes(config.Nh)

    # set up server and listen for connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(SOCKET)
        server.listen(1)

        while True:
            logging.info("Listening for connections, ctrl+c to exit")
            try:

                # accept incoming connections and handle them
                connection, address = server.accept()
                logging.info(f"Connection received from {address}")
                with connection: # auto close when leave 'with' scope
                    handle_connection(connection, config, oprf_seed, pkS_bytes, records, skS, pkS, fake_record)

            # upon ctrl-c, exit
            except KeyboardInterrupt:
                logging.info("Exiting")
                break

# if run but not imported, run the server with the default OPRF configuration
if __name__ == "__main__":
    main(CONFIG)
