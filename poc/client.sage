"""
Command-line interface for an OPAQUE client allowing them to register a username
and password, and login with a username and password in any combination.
Communicates with the server using a socket.
"""

import logging
import socket
import sys
from typing import Tuple, Union

try:
    from sagelib.opaque_ake import Configuration, OPAQUE3DH
    from sagelib.opaque_common import _as_bytes
    from sagelib.opaque_core import OPAQUECore
    from sagelib.opaque_messages import deserialize_registration_response, deserialize_credential_response
    from sagelib.server import SOCKET, Mode, CONFIG, IDS, RECV_LEN, RNG, formatKE1, formatKE2, formatKE3
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

def client_registration(connection: socket.socket, config: Configuration,
                        idU: bytes, pwdU: bytes) -> Union[bytes, None]:
    """
    Run the client's registration flow to store its credentials on the server.

    The client inputs its username and password (encoded as bytes) and outputs
    an export key which can be used for application-specific purposes like
    encrypting additional information to the server. config is the OPRF
    settings that the client and server will use.

    If this username has already been registered then return None.
    """

    logging.info("Starting registration")

    core = OPAQUECore(config, RNG)

    # create the registration request
    request, blind = core.create_registration_request(pwdU)

    # serialise and send the registration request
    connection.send(request.serialize())
    logging.info(f"Sent request:\n{request}")

    # receive and deserialise the registration response
    serialized_response = connection.recv(RECV_LEN)
    try:
        response = deserialize_registration_response(config, serialized_response)
    except: # if this fails, the username has already been registered
        logging.warning("Username already registered\n")
        return None

    logging.info(f"Received response:\n{response}")

    # finalise request, create record and derive export key
    record, export_key = core.finalize_request(pwdU, blind, response, idU, IDS)

    # serialise and send the record
    connection.send(record.serialize())
    logging.info(f"Sent record:\n{record}")

    logging.info(f"Derived export key:\nExport key: {export_key.hex()}")

    logging.info("Completed registration\n")

    return export_key

def client_login_no_ake(connection: socket.socket, config: Configuration,
                 idU: bytes, pwdU: bytes) -> Tuple[Union[bytes, None],
                 Union[bytes, None], Union[bytes, None]]:
    """
    Run the client's login flow without AKE to retrieve the credentials
    stored on the server during registration.

    The client inputs its username and password which should be already
    registered and outputs an export key which can be used for application-
    specific purposes like encrypting additional information on the server.
    The client also outputs the client's private key and the server's public
    key encoded as bytes.

    If the username and/or password are incorrect, all return values are None.

    config is the OPRF settings that the client and server will use.
    """

    logging.info("Starting login without AKE")

    core = OPAQUECore(config, RNG)

    # create the credential request
    request, blind = core.create_credential_request(pwdU)

    # serialise and send the credential request
    connection.send(request.serialize())
    logging.info(f"Sent request:\n{request}")

    # receive and deserialise the credential response
    serialized_response = connection.recv(RECV_LEN)
    response, _ = deserialize_credential_response(config, serialized_response)
    logging.info(f"Received response:\n{response}")

    # recover credentials and derive export key
    try:
        skU_bytes, pkS_bytes, export_key = core.recover_credentials(pwdU, blind, response, idU, IDS)
    except:
        logging.warning("Invalid username and/or password\n")
        return None, None, None

    logging.info(f"Derived export key:\nExport key: {export_key.hex()}")

    logging.info("Completed login without AKE and successfully recovered credentials\n")

    return export_key, skU_bytes, pkS_bytes

def client_login_ake(connection: socket.socket, config: Configuration,
                     idU: bytes, pwdU: bytes) -> Tuple[Union[bytes, None],
                                                            Union[bytes, None]]:
    """
    Run the client's login flow with authenticated key exchange to retrieve the
    credentials stored on the server during registration and establish a shared
    secret session key.

    The client inputs its username and password which should be already
    registered and outputs an export key which can be used for application-
    specific purposes like encrypting additional information on the server as
    well as a shared secret session key which the server also has, facilitating
    further communication.

    If the username and/or password are incorrect, both return values are None.

    config is the OPRF settings that the client and server will use.
    """

    logging.info("Starting login with AKE")

    kex = OPAQUE3DH(config, RNG)

    # create ke1
    serialized_ke1 = kex.generate_ke1(pwdU)

    # send ke1
    connection.send(serialized_ke1)
    logging.info(f"Sent ke1:\n{formatKE1(config, serialized_ke1)}")

    # receive ke2
    serialized_ke2 = connection.recv(RECV_LEN)

    # recover credentials and derive export and session keys
    try:

        # don't provide pkU because it is only required if idU is not provided,
        # but we always use idU
        serialized_ke3 = kex.generate_ke3(serialized_ke2, idU, None, IDS)
    except:
        logging.warning("Invalid username and/or password\n")
        return None, None

    logging.info(f"Received ke2:\n{formatKE2(config, serialized_ke2)}")

    # send ke3 so server can generate key too
    connection.send(serialized_ke3)
    logging.info(f"Sent ke3:\n{formatKE3(config, serialized_ke3)}")

    logging.info(f"Derived session key:\nSession key: {kex.session_key.hex()}")
    logging.info(f"Derived export key:\nExport key: {kex.export_key.hex()}")

    logging.info("Completed login with AKE and successfully recovered credentials\n")

    return kex.export_key, kex.session_key

class Client:
    """
    Facilitate easy envoking of client registration and login (with and without
    AKE) methods to test them - just return whether successful.
    """

    def __init__(self, config: Configuration):
        self.config = config

    def do(self, username: str, password: str, mode: Mode) -> bool:
        """
        Connect to the server and run the flow according to 'mode' which must
        be an instance of 'Mode' to determine what to do - register, login
        without AKE, or login with AKE.

        Return whether successful. Registration is unsuccessful iff that
        username has already been registered, login (with and without ake) is
        unsuccessful iff the username or password is incorrect.

        This immediately tries to connect to the server and if unsuccessful, an
        exception will be thrown, so ensure the server is running first by
        running 'make runserver'.
        """

        assert isinstance(mode, Mode), "Mode must be an instance of 'Mode' from `server.sage`"

        # encode username and password as bytes
        idU = _as_bytes(username)
        pwdU = _as_bytes(password)

        # connect to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            try:
                connection.connect(SOCKET)
            except Exception as e:
                logging.error("Server not up, run 'make runserver'")
                exit(1)

            # send mode followed by colon followed by username
            connection.send((mode.value + ":").encode() + idU)

            # for registration, get an export key
            if mode is Mode.REGISTRATION:
                export_key = client_registration(connection, self.config, idU, pwdU)

                # successful (username unregistered) iff export_key is not None
                return export_key is not None

            # for login without AKE, get an export key and credentials stored
            # on the server - the client's private key and server's public key
            elif mode is Mode.LOGIN_NO_AKE:
                export_key, skU_bytes, pkS_bytes = client_login_no_ake(connection, self.config, idU, pwdU)

                # successful (username & password correct) iff export_key is
                # not None
                return export_key is not None

            # for login with AKE, get an export key and session key that the
            # server also has to facilitate further communication
            else:
                export_key, session_key = client_login_ake(connection, self.config, idU, pwdU)

                # successful (username & password correct) iff export_key is
                # not None
                return export_key is not None

def main(config: Configuration):
    """
    Run the command-line client to repeatedly take mode, username and password
    from the user, connect to the server and run that flow. Use config as the
    OPRF configuration.
    """

    # logging format - log everything and add 'client' to front of messages
    logging.basicConfig(level=logging.INFO, format="Client %(levelname)s: %(message)s")

    client = Client(config)

    while True:

        # get mode from the user
        inp = input(f"Register ({Mode.REGISTRATION.value}) or login without " + 
            f"AKE (Authenticated Key Exchange) ({Mode.LOGIN_NO_AKE.value}) " +
            f"or login with AKE ({Mode.LOGIN_AKE.value}) or quit (q)? ")

        # if the user wanted to quit, exit
        if inp == "q":
            break

        # if the user input an invalid mode, restart loop to ask again
        if inp not in [Mode.REGISTRATION.value, Mode.LOGIN_NO_AKE.value, Mode.LOGIN_AKE.value]:
            print(f"Must enter '{Mode.REGISTRATION.value}', '{Mode.LOGIN_NO_AKE.value}', '{Mode.LOGIN_AKE.value}', or 'q'")
            continue

        # get username and password from the user
        username = input("Username: ")
        password = input("Password: ")

        # run the relevant flow
        client.do(username, password, Mode.get(inp))

# if run but not imported, run the command-line client with the default OPRF
# configuration
if __name__ == "__main__":
    main(CONFIG)
