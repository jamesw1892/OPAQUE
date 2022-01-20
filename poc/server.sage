"""
Single-threaded server for OPAQUE allowing one client at a time to connect
using a socket and either register a username and password, or login with a
username and password.
Lots taken from `test_opaque_ake.sage`.
"""

import socket
import sys
import logging
from typing import Dict

from sagelib.opaque_common import zero_bytes

try:
    from sagelib.opaque_ake import Configuration
    from sagelib.opaque_common import random_bytes, _as_bytes
    from sagelib.opaque_core import OPAQUECore
    from sagelib.opaque_messages import deserialize_registration_request, deserialize_registration_upload, deserialize_credential_request, RegistrationUpload, Envelope
    from sagelib.test_opaque_ake import default_opaque_configuration
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

# use localhost for testing
SOCKET = ("127.0.0.1", 1337)

# configuration to use
CONFIG = default_opaque_configuration

# determine what mode the client is doing
REGISTRATION = "registration"
LOGIN = "login"

# create a fake record that we can use if the client has not previously registered
# we still do the login flow to prevent client enumeration
# recommended https://www.ietf.org/archive/id/draft-irtf-cfrg-opaque-07.html#section-6.3.2.2-4
FAKE_RECORD = RegistrationUpload(random_bytes(CONFIG.Npk), random_bytes(CONFIG.Nh),
                                 Envelope(zero_bytes(CONFIG.Nn), zero_bytes(CONFIG.Nm)))

def server_registration(config: Configuration, connection: socket.socket,
        idU: bytes, pkS_enc: bytes, oprf_seed: bytes) -> RegistrationUpload:
    """
    Run the server's registration flow to store the client's credentials.
    The server inputs its parameters (config). idU is the client's username
    that has already been received from the client. The output is the record of
    the client to be stored
    """

    logging.info("Starting registration")

    core = OPAQUECore(config)

    # receive and deserialise registration request
    serialized_request = connection.recv(1024)
    request = deserialize_registration_request(config, serialized_request)
    logging.info(f"Received request:\n{request}")

    # create response
    response, kU = core.create_registration_response(request, pkS_enc, oprf_seed, idU, _as_bytes(""))

    # send
    connection.send(response.serialize())
    logging.info(f"Sent response:\n{response}")

    # receive the record
    serialized_record = connection.recv(1024)
    record = deserialize_registration_upload(config, serialized_record)
    logging.info(f"Received record:\n{record}")

    logging.info("Completed registration\n")

    return record

def server_login(config: Configuration, record: RegistrationUpload, connection: socket.socket, idU: bytes, pkS_enc: bytes, oprf_seed: bytes):
    """
    Run the server's login flow to send the client's credentials. Their record
    that was stored has already been retrieved and is 'record'.
    """

    logging.info("Starting login")

    core = OPAQUECore(config)

    # receive and deserialise credential request
    serialized_request = connection.recv(1024)
    cred_request, _ = deserialize_credential_request(config, serialized_request)
    logging.info(f"Received request:\n{cred_request}")

    # in production, would receive AKE message 1 (AuthInit) here too, then
    # calculate AuthResponse as specified by the particular AKE used

    # create credential response
    cred_response = core.create_credential_response(cred_request, pkS_enc, oprf_seed, record.envU, idU, record.masking_key, _as_bytes(""))

    # send credential response
    connection.send(cred_response.serialize())
    logging.info(f"Sent response:\n{cred_response}")

    # in production, would send AKE message 2 (AuthResponse) here too, then
    # receive AKE message 3 (AuthFinish) and derive a session_key from it to return

    logging.info("Completed login\n")

def handle_connection(connection: socket.socket, records: Dict[bytes, RegistrationUpload], pkS_enc: bytes, oprf_seed: bytes):

    # the first message is the mode followed by a colon
    # then the username followed by a colon
    msg = connection.recv(1024).decode().split(":")
    mode = msg[0]
    idU = msg[1].encode() # keep username as bytes

    # send back mode to confirm receipt
    connection.send(mode.encode())

    if mode == REGISTRATION:
        record = server_registration(CONFIG, connection, idU, pkS_enc, oprf_seed)
        records[idU] = record
    elif mode == LOGIN:
        if idU in records:
            record = records[idU]
            logging.info("Record exists")
        else: # if record not found, still do the login flow to prevent client enumeration
            record = FAKE_RECORD
            logging.info("Record faked")
        server_login(CONFIG, record, connection, idU, pkS_enc, oprf_seed)
    else:
        logging.error("Invalid mode")

def main():

    # logging format
    logging.basicConfig(level=logging.INFO, format="Server %(levelname)s: %(message)s")

    # stores registered credentials
    records = dict()

    # generate server's public and private keypair and OPRF seed
    group = CONFIG.group
    skS, pkS = group.key_gen()
    pkS_enc = group.serialize(pkS)
    oprf_seed = random_bytes(CONFIG.oprf_suite.group.scalar_byte_length())

    # set up server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(SOCKET)

        # wait for connections and accept when one comes
        server.listen(1)

        while True:
            logging.info("Listening for connections...")
            try:
                connection, address = server.accept()
                logging.info(f"Connection received from {address}")
                with connection: # auto close when leave 'with' scope
                    # threading._start_new_thread(handle_connection, server.accept())
                    handle_connection(connection, records, pkS_enc, oprf_seed)
            except KeyboardInterrupt:
                logging.info("Exiting")
                break

            # print stored records
            # print("\n\nRecords:")
            # for idU in records:
            #     username = idU.decode()
            #     record = records[idU]
            #     print(f"{username}: {record}")
            # print("\n")

if __name__ == "__main__":
    main()
