#!/usr/bin/sage
# vim: syntax=python

import sys
import hmac

from collections import namedtuple

try:
    from sagelib.opaque_common import derive_secret, hkdf_expand_label, hkdf_extract, I2OSP, OS2IP, OS2IP_le, encode_vector, encode_vector_len, to_hex, OPAQUE_NONCE_LENGTH
    from sagelib.opaque_core import OPAQUECore, OPAQUE_SEED_LENGTH
    from sagelib.opaque_messages import deserialize_credential_request, deserialize_credential_response
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

class Configuration(object):
    def __init__(self, oprf_suite, kdf, mac, hash, ksf, group, context):
        self.oprf_suite = oprf_suite
        self.kdf = kdf
        self.mac = mac
        self.hash = hash
        self.ksf = ksf
        self.group = group
        self.context = context
        self.Npk = group.element_byte_length()
        self.Nsk = group.scalar_byte_length()
        self.Nm = mac.output_size()
        self.Nx = hash().digest_size
        self.Nok = oprf_suite.group.scalar_byte_length()
        self.Nh = hash().digest_size
        self.Nn = OPAQUE_NONCE_LENGTH
        self.Ne = self.Nn + self.Nm

class KeyExchange(object):
    def __init__(self):
        pass

    def json(self):
        raise Exception("Not implemented")

    def generate_ke1(self, l1):
        raise Exception("Not implemented")

    def generate_ke2(self, l1, l2, ke1, client_public_key, server_private_key, server_public_key):
        raise Exception("Not implemented")

    def generate_ke3(self, l2, ake2, ke1_state, server_public_key, client_private_key, client_public_key):
        raise Exception("Not implemented")

TripleDHComponents = namedtuple("TripleDHComponents", "pk1 sk1 pk2 sk2 pk3 sk3")

class OPAQUE3DH(KeyExchange):
    def __init__(self, config, rng):
        self.config = config
        self.core = OPAQUECore(config, rng)
        self.rng = rng

    def json(self):
        return {
            "Name": "3DH",
            "Group": self.config.group.name,
            "OPRF": self.config.oprf_suite.identifier,
            "KDF": self.config.kdf.name,
            "MAC": self.config.mac.name,
            "Hash": self.config.hash().name.upper(),
            "KSF": self.config.ksf.name,
            "Context": to_hex(self.config.context),
            "Nh": str(self.config.Nh),
            "Npk": str(self.config.Npk),
            "Nsk": str(self.config.Nsk),
            "Nm": str(self.config.Nm),
            "Nx": str(self.config.Nx),
            "Nok": str(self.config.Nok),
        }

    def derive_3dh_keys(self, dh_components, info):
        dh1 = self.config.group.scalar_mult(dh_components.sk1, self.config.group.deserialize(dh_components.pk1))
        dh2 = self.config.group.scalar_mult(dh_components.sk2, self.config.group.deserialize(dh_components.pk2))
        dh3 = self.config.group.scalar_mult(dh_components.sk3, self.config.group.deserialize(dh_components.pk3))

        dh1_encoded = self.config.group.serialize(dh1)
        dh2_encoded = self.config.group.serialize(dh2)
        dh3_encoded = self.config.group.serialize(dh3)
        ikm = dh1_encoded + dh2_encoded + dh3_encoded

        prk = hkdf_extract(self.config, bytes([]), ikm)
        handshake_secret = derive_secret(self.config, prk, _as_bytes("HandshakeSecret"), info)
        session_key = derive_secret(self.config, prk, _as_bytes("SessionKey"), info)

        # client_mac_key = HKDF-Expand-Label(handshake_secret, "ClientMAC", "", Hash.length)
        # server_mac_key = HKDF-Expand-Label(handshake_secret, "ServerMAC", "", Hash.length)
        # handshake_encrypt_key = HKDF-Expand-Label(handshake_secret, "HandshakeKey", "", key_length)
        Nh = self.config.hash().digest_size
        empty_info = bytes([])
        server_mac_key = hkdf_expand_label(self.config, handshake_secret, _as_bytes("ServerMAC"), empty_info, Nh)
        client_mac_key = hkdf_expand_label(self.config, handshake_secret, _as_bytes("ClientMAC"), empty_info, Nh)

        return server_mac_key, client_mac_key, session_key, handshake_secret

    def auth_client_start(self):
        self.client_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        self.client_keyshare_seed = self.rng.random_bytes(OPAQUE_SEED_LENGTH)
        self.client_private_keyshare, self.client_public_keyshare = self.core.derive_diffie_hellman_key_pair(self.client_keyshare_seed)
        return TripleDHMessageInit(self.client_nonce, self.client_public_keyshare)

    def generate_ke1(self, password):
        cred_request, cred_metadata = self.core.create_credential_request(password)
        self.serialized_request = cred_request.serialize()
        self.cred_metadata = cred_metadata
        self.password = password

        ke1 = self.auth_client_start()

        return self.serialized_request + ke1.serialize()

    def transcript_hasher(self, serialized_request, serialized_response, cleartext_credentials, client_nonce, client_public_keyshare, server_nonce, server_public_keyshare_bytes):
        hasher = self.config.hash()
        hasher.update(_as_bytes("RFCXXXX"))                                         # RFCXXXX
        hasher.update(encode_vector(self.config.context))                           # context
        hasher.update(encode_vector_len(cleartext_credentials.client_identity, 2))  # client_identity
        hasher.update(serialized_request)                                           # ke1: cred request
        hasher.update(client_nonce)                                                 # ke1: client nonce
        hasher.update(client_public_keyshare)                                 # ke1: client keyshare
        hasher.update(encode_vector_len(cleartext_credentials.server_identity, 2))  # server identity
        hasher.update(serialized_response)                                          # ke2: cred response
        hasher.update(server_nonce)                                                 # ke2: server nonce
        hasher.update(server_public_keyshare_bytes)                                 # ke2: server keyshare

        self.hasher = hasher

        return hasher.digest()

    def auth_server_respond(self, cred_request, cred_response, ke1, cleartext_credentials, server_private_key, client_public_keyshare):
        self.server_nonce = self.rng.random_bytes(OPAQUE_NONCE_LENGTH)
        self.server_keyshare_seed = self.rng.random_bytes(OPAQUE_SEED_LENGTH)
        self.server_private_keyshare, self.server_public_keyshare_bytes = self.core.derive_diffie_hellman_key_pair(self.server_keyshare_seed)

        transcript_hash = self.transcript_hasher(cred_request.serialize(), cred_response.serialize(), cleartext_credentials, ke1.client_nonce, ke1.client_public_keyshare, self.server_nonce, self.server_public_keyshare_bytes)

        # K3dh = epkU^eskS || epkU^skS || pkU^eskS
        dh_components = TripleDHComponents(ke1.client_public_keyshare, self.server_private_keyshare, ke1.client_public_keyshare, server_private_key, client_public_keyshare, self.server_private_keyshare)

        server_mac_key, client_mac_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, self.hasher.digest())
        mac = hmac.digest(server_mac_key, transcript_hash, self.config.hash)
        ake2 = TripleDHMessageRespond(self.server_nonce, self.server_public_keyshare_bytes, mac)

        self.server_mac_key = server_mac_key
        self.ake2 = ake2
        self.client_mac_key = client_mac_key
        self.session_key = session_key
        self.server_mac = mac
        self.handshake_secret = handshake_secret

        return ake2

    def generate_ke2(self, msg, oprf_seed, credential_identifier, envU, masking_key, server_identity, server_private_key, server_public_keyshare, client_identity, client_public_keyshare):
        cred_request, offset = deserialize_credential_request(self.config, msg)
        ke1 = deserialize_tripleDH_init(self.config, msg[offset:])

        cred_response = self.core.create_credential_response(cred_request, server_public_keyshare, oprf_seed, envU, credential_identifier, masking_key)
        serialized_response = cred_response.serialize()
        self.masking_nonce = cred_response.masking_nonce

        cleartext_credentials = self.core.create_cleartext_credentials(server_public_keyshare, client_public_keyshare, server_identity, client_identity)
        ake2 = self.auth_server_respond(cred_request, cred_response, ke1, cleartext_credentials, server_private_key, client_public_keyshare)

        return serialized_response + ake2.serialize()

    def auth_client_finalize(self, cred_response, ake2, cleartext_credentials, client_private_key):
        transcript_hash = self.transcript_hasher(self.serialized_request, cred_response.serialize(), cleartext_credentials, self.client_nonce, self.client_public_keyshare, ake2.server_nonce, ake2.server_public_keyshare_bytes)

        # K3dh = epkS^eskU || pkS^eskU || epkS^skU
        dh_components = TripleDHComponents(ake2.server_public_keyshare_bytes, self.client_private_keyshare, cleartext_credentials.server_public_key_bytes, self.client_private_keyshare, ake2.server_public_keyshare_bytes, client_private_key)

        server_mac_key, client_mac_key, session_key, handshake_secret = self.derive_3dh_keys(dh_components, self.hasher.digest())
        server_mac = hmac.digest(server_mac_key, transcript_hash, self.config.hash)
        assert server_mac == ake2.mac

        self.session_key = session_key
        self.server_mac_key = server_mac_key
        self.client_mac_key = client_mac_key
        self.handshake_secret = handshake_secret

        # transcript3 == transcript2, plus server_mac
        self.hasher.update(server_mac)
        transcript_hash = self.hasher.digest()

        client_mac = hmac.digest(client_mac_key, transcript_hash, self.config.hash)

        return TripleDHMessageFinish(client_mac)

    def generate_ke3(self, msg, client_identity, server_identity):
        cred_response, offset = deserialize_credential_response(self.config, msg)
        ake2 = deserialize_tripleDH_respond(self.config, msg[offset:])
        client_private_key_bytes, cleartext_credentials, export_key = self.core.recover_credentials(self.password, self.cred_metadata, cred_response, client_identity, server_identity)

        if "curve25519" in self.config.group.name:
            client_private_key = client_private_key_bytes
        elif "ristretto" in self.config.group.name or "decaf" in self.config.group.name:
            client_private_key = OS2IP_le(client_private_key_bytes)
        else:
            client_private_key = OS2IP(client_private_key_bytes)

        self.export_key = export_key
        ke3 = self.auth_client_finalize(cred_response, ake2, cleartext_credentials, client_private_key)

        return ke3.serialize()

    def auth_server_finish(self, msg):
        ke3 = deserialize_tripleDH_finish(self.config, msg)

        client_mac_key = self.client_mac_key
        self.hasher.update(self.server_mac)
        transcript_hash = self.hasher.digest()

        client_mac = hmac.digest(client_mac_key, transcript_hash, self.config.hash)
        assert client_mac == ke3.mac

        return self.session_key

# struct {
#      opaque client_nonce[32];
#      opaque client_public_keyshare[LK];
#  } KE1M;
def deserialize_tripleDH_init(config, data):
    client_nonce = data[0:OPAQUE_NONCE_LENGTH]
    client_public_keyshare = data[OPAQUE_NONCE_LENGTH:]
    length = config.oprf_suite.group.element_byte_length()
    if len(client_public_keyshare) != length:
        raise Exception("Invalid client_public_keyshare length: %d %d" % (len(client_public_keyshare), length))
    return TripleDHMessageInit(client_nonce, client_public_keyshare)

class TripleDHMessageInit(object):
    def __init__(self, client_nonce, client_public_keyshare):
        self.client_nonce = client_nonce
        self.client_public_keyshare = client_public_keyshare

    def serialize(self):
        return self.client_nonce + self.client_public_keyshare

    def __str__(self):
        return f"TripleDHMessageInit(nonceU={self.client_nonce.hex()}, epkU={self.client_public_keyshare.hex()})"

# struct {
#      opaque server_nonce[32];
#      opaque server_public_keyshare[LK];
#      opaque mac[LH];
#  } KE2M;
def deserialize_tripleDH_respond(config, data):
    length = config.oprf_suite.group.element_byte_length()
    server_nonce = data[0:OPAQUE_NONCE_LENGTH]
    server_public_keyshare_bytes = data[OPAQUE_NONCE_LENGTH:OPAQUE_NONCE_LENGTH+length]
    mac = data[OPAQUE_NONCE_LENGTH+length:]
    if len(mac) != config.hash().digest_size:
        raise Exception("Invalid MAC length: %d %d" % (len(mac), config.hash().digest_size))
    return TripleDHMessageRespond(server_nonce, server_public_keyshare_bytes, mac)

class TripleDHMessageRespond(object):
    def __init__(self, server_nonce, server_public_keyshare_bytes, mac):
        self.server_nonce = server_nonce
        self.server_public_keyshare_bytes = server_public_keyshare_bytes
        self.mac = mac

    def serialize(self):
        return self.server_nonce + self.server_public_keyshare_bytes + self.mac

    def __str__(self):
        return f"TripleDHMessageRespond(nonceS={self.server_nonce.hex()}, epkS={self.server_public_keyshare_bytes.hex()}, macS={self.mac.hex()})"

# struct {
#      opaque mac[LH];
#  } KE3M;
def deserialize_tripleDH_finish(config, data):
    if len(data) != config.hash().digest_size:
        raise Exception("Invalid MAC length: %d %d" % (len(data), config.hash().digest_size))
    return TripleDHMessageFinish(data)

class TripleDHMessageFinish(object):
    def __init__(self, mac):
        self.mac = mac

    def serialize(self):
        return self.mac

    def __str__(self):
        return f"TripleDHMessageFinish(macU={self.mac.hex()})"
