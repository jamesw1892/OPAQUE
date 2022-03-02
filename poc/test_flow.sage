"""
Test the client and server by acting as a client
"""

import logging
import sys

try:
    from sagelib.client import Client
    from sagelib.server import Mode, CONFIG
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

logging.basicConfig(level=logging.INFO, format="Test %(levelname)s: %(message)s")

client = Client(CONFIG)

logging.info("Testing registration")
assert client.do("j", "p", Mode.REGISTRATION)

logging.info("Testing login without AKE with correct credentials")
assert client.do("j", "p", Mode.LOGIN_NO_AKE)

logging.info("Testing login with AKE with correct credentials")
assert client.do("j", "p", Mode.LOGIN_AKE)

logging.info("Testing login without AKE with incorrect password")
assert not client.do("j", "q", Mode.LOGIN_NO_AKE)

logging.info("Testing login with AKE with incorrect password")
assert not client.do("j", "q", Mode.LOGIN_AKE)

logging.info("Testing login without AKE with unregistered username")
assert not client.do("k", "p", Mode.LOGIN_NO_AKE)

logging.info("Testing login with AKE with unregistered username")
assert not client.do("k", "p", Mode.LOGIN_AKE)

# register and login with another username
assert client.do("k", "p", Mode.REGISTRATION)
assert client.do("k", "p", Mode.LOGIN_NO_AKE)

logging.info("Testing login without AKE with not the most recent credentials used")
assert client.do("j", "p", Mode.LOGIN_NO_AKE)

logging.info("Testing login with AKE with not the most recent credentials used")
assert client.do("k", "p", Mode.LOGIN_AKE)
assert client.do("j", "p", Mode.LOGIN_AKE)

logging.info("Testing registration with an already registered username")
assert not client.do("j", "r", Mode.REGISTRATION)

logging.info("All tests passed!")
