"""
Command-line interface for an OPAQUE client allowing them to register a username
and password, and login with a username and password in any combination.
Communicates with the server using a socket.
Lots taken from `test_opaque_ake.sage`.
"""

import socket
import sys
import logging

try:
    from sagelib.opaque_ake import Configuration
    from sagelib.opaque_common import _as_bytes
    from sagelib.opaque_core import OPAQUECore
    from sagelib.opaque_messages import deserialize_registration_response, deserialize_credential_response, Credentials
    from sagelib.server import SOCKET, REGISTRATION, LOGIN, CONFIG
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def client_registration(config: Configuration, username: str, password: str) -> bytes:
    """
    Run the client's registration flow to register the client with the server.
    The client inputs its username and password and the export key is output
    which can be used for application-specific purposes like encrypting
    additional information to the server.
    This tries to connect to the server immediately so it must be running
    """

    logging.info("Starting registration")

    idU = _as_bytes(username)
    pwdU = _as_bytes(password)

    # connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:

        try:
            client.connect(SOCKET)
        except:
            logging.error("Server not up, run 'make runserver'")
            return

        # send mode followed by colon followed by username
        client.send((REGISTRATION + ":").encode() + idU)

        if client.recv(1024).decode() != REGISTRATION:
            logging.error("Mode receipt not confirmed")
            return

        group = config.group
        skU, pkU = group.key_gen()
        skU_enc = group.serialize_scalar(skU)
        pkU_enc = group.serialize(pkU)

        core = OPAQUECore(config)
        creds = Credentials(skU_enc, pkU_enc)

        request, metadata = core.create_registration_request(pwdU)

        # send the registration request
        client.send(request.serialize())
        logging.info(f"Sent request:\n{request}")

        # receive the registration response
        serialized_response = client.recv(1024)
        response = deserialize_registration_response(config, serialized_response)
        logging.info(f"Received response:\n{response}")

        # finalise request and create record
        record, export_key = core.finalize_request(creds, pwdU, metadata, response, _as_bytes(""))

        # send record
        client.send(record.serialize())
        logging.info(f"Sent record:\n{record}")

    logging.info("Completed registration\n")

    return export_key

def client_login(config: Configuration, username: str, password: str) -> bytes:
    """
    Run the client's login flow to retrieve the credentials stored during
    registration. The client inputs its username and password which should be
    already registered. The 
    """

    logging.info("Starting login")

    idU = _as_bytes(username)
    pwdU = _as_bytes(password)

    # create the socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect the socket to the server
    client.connect(SOCKET)

    # send mode followed by colon followed by username
    client.send((LOGIN + ":").encode() + idU)

    if client.recv(1024).decode() != LOGIN:
        logging.error("Mode receipt not confirmed")
        return

    core = OPAQUECore(config)

    cred_request, cred_metadata = core.create_credential_request(pwdU)

    # in production, would create AKE message 1 (AuthInit) here too and send it

    # send the credential request
    client.send(cred_request.serialize())
    logging.info(f"Sent request:\n{cred_request}")

    # receive the credential response
    serialized_response = client.recv(1024)
    cred_response, _ = deserialize_credential_response(config, serialized_response)
    logging.info(f"Received response:\n{cred_response}")

    # in production, would receive AKE message 2 (AuthResponse) here too, then
    # derive session_key from it to return with the export key. From
    # AuthResponse and skU and pkS calculated below, we also calculate AKE
    # message 3 (AuthFinish) and send it to the server

    # finalise request and create record
    try:
        skU, pkS, export_key = core.recover_credentials(pwdU, cred_metadata, cred_response, _as_bytes(""))
    except:
        logging.warning("Invalid username and/or password\n")
        return

    # close the socket
    client.close()

    logging.info("Completed login and recovered credentials\n")

    return export_key

def main():

    # logging format
    logging.basicConfig(level=logging.INFO, format="Client %(levelname)s: %(message)s")

    while True:

        inp = input("Register (r) or login (l) or quit (q)? ")
        if inp == "q":
            break
        if inp != "r" and inp != "l":
            print("Must enter 'r', 'l', or 'q'")
            continue

        username = input("Username: ")
        password = input("Password: ")

        if inp == "r":
            client_registration(CONFIG, username, password)
        else:
            client_login(CONFIG, username, password)

if __name__ == "__main__":
    main()
