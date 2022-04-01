#!/usr/bin/sage
# vim: syntax=python

import sys

try:
    from sagelib.opaque_common import encode_vector, OPAQUE_NONCE_LENGTH
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + e)

# struct {
#   uint8 server_public_key[Npk];
#   uint8 server_identity<1..2^16-1>;
#   uint8 client_identity<1..2^16-1>;
# } CleartextCredentials;
class CleartextCredentials(object):
    def __init__(self, pkS, idU, idS):
        self.pkS = pkS
        self.idU = idU
        self.idS = idS

    def serialize(self):
        return self.pkS + encode_vector(self.idS) + encode_vector(self.idU)

    def __str__(self):
        return f"CleartextCredentials(pkS={self.pkS.hex()}, idU={self.idU.hex()}, idS={self.idS.hex()})"

class Credentials(object):
    def __init__(self, skU, pkU, idU = None, idS = None):
        self.skU = skU
        self.pkU = pkU
        self.idU = idU
        self.idS = idS

    def __str__(self):
        return f"Credentials(skU={self.skU.hex()}, pkU={self.pkU.hex()}, idU={self.idU.hex()}, idS={self.idS.hex()})"

# struct {
#   opaque nonce[Nn];
#   opaque auth_tag[Nm];
# } Envelope;
def deserialize_envelope(config, data):

    # TODO(caw): put Nm in the config
    Nm = config.hash().digest_size
    if len(data) != OPAQUE_NONCE_LENGTH + Nm:
         raise Exception("Invalid envelope length")

    nonce = data[:OPAQUE_NONCE_LENGTH]
    auth_tag = data[OPAQUE_NONCE_LENGTH:]

    return Envelope(nonce, auth_tag), OPAQUE_NONCE_LENGTH+Nm

class Envelope(object):
    def __init__(self, nonce, auth_tag):
        self.nonce = nonce
        self.auth_tag = auth_tag

    def serialize(self):
        return self.nonce + self.auth_tag

    def __eq__(self, other):
        if isinstance(other, Envelope):
            serialized = self.serialize()
            other_serialized = other.serialize()
            return serialized == other_serialized
        return False

    def __str__(self):
        return f"Envelope(nonce={self.nonce.hex()}, auth_tag={self.auth_tag.hex()})"

class ProtocolMessage(object):
    def __init__(self):
        pass

    def serialize(self):
        raise Exception("Not implemented")

    def __eq__(self, other):
        if isinstance(other, ProtocolMessage):
            serialized = self.serialize()
            other_serialized = other.serialize()
            return serialized == other_serialized
        return False

# struct {
#     opaque blinded_message[Noe];
# } RegistrationRequest;
def deserialize_registration_request(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    if len(msg_bytes) < length:
        raise Exception("Invalid message")
    return RegistrationRequest(msg_bytes[0:length])

class RegistrationRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return self.data

    def __str__(self):
        return f"RegistrationRequest(data={self.data.hex()})"

# struct {
#     opaque evaluated_message[Noe];
#     opaque pkS[Npk];
# } RegistrationResponse;
def deserialize_registration_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    pkS = msg_bytes[length:]
    if len(pkS) != config.Npk:
        raise Exception("Invalid message: %d %d" % (len(pkS), config.Npk))

    return RegistrationResponse(data, pkS)

class RegistrationResponse(ProtocolMessage):
    def __init__(self, data, pkS):
        ProtocolMessage.__init__(self)
        self.data = data
        self.pkS = pkS

    def serialize(self):
        return self.data + self.pkS

    def __str__(self):
        return f"RegistrationResponse(data={self.data.hex()}, pkS={self.pkS.hex()})"

# struct {
#     opaque pkU[Npk];
#     opaque masking_key[Nh];
#     Envelope envU;
# } RegistrationUpload;
def deserialize_registration_upload(config, msg_bytes):
    if len(msg_bytes) < config.Npk:
        raise Exception("Invalid message")
    pkU = msg_bytes[:config.Npk]

    Nh = config.hash().digest_size
    masking_key = msg_bytes[config.Npk:config.Npk+Nh]

    envU, _ = deserialize_envelope(config, msg_bytes[config.Npk+Nh:])

    return RegistrationUpload(pkU, masking_key, envU)

class RegistrationUpload(ProtocolMessage):
    def __init__(self, pkU, masking_key, envU):
        ProtocolMessage.__init__(self)
        self.pkU = pkU
        self.masking_key = masking_key
        self.envU = envU

    def serialize(self):
        return self.pkU + self.masking_key + self.envU.serialize()

    def __str__(self):
        return f"RegistrationUpload(pkU={self.pkU.hex()}, masking_key={self.masking_key.hex()}, envU={self.envU})"

# struct {
#     opaque blinded_message[Noe];
# } CredentialRequest;
def deserialize_credential_request(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    if len(msg_bytes) < length:
        raise Exception("Invalid message")
    return CredentialRequest(msg_bytes[0:length]), length

class CredentialRequest(ProtocolMessage):
    def __init__(self, data):
        ProtocolMessage.__init__(self)
        self.data = data

    def serialize(self):
        return self.data

    def __str__(self):
        return f"CredentialRequest(data={self.data.hex()})"

# struct {
#     opaque evaluated_message[Noe];
#     opaque masking_nonce[32];
#     opaque masked_response[Npk + Ne];
# } CredentialResponse;
def deserialize_credential_response(config, msg_bytes):
    length = config.oprf_suite.group.element_byte_length()
    data = msg_bytes[0:length]
    masking_nonce = msg_bytes[length:length+OPAQUE_NONCE_LENGTH]

    Nm = config.hash().digest_size
    Npk = config.Npk
    Ne = Nm + OPAQUE_NONCE_LENGTH
    masked_response = msg_bytes[length+OPAQUE_NONCE_LENGTH:length+OPAQUE_NONCE_LENGTH+Npk+Ne]
    return CredentialResponse(data, masking_nonce, masked_response), length+OPAQUE_NONCE_LENGTH+Npk+Ne

class CredentialResponse(ProtocolMessage):
    def __init__(self, data, masking_nonce, masked_response):
        ProtocolMessage.__init__(self)
        self.data = data
        self.masking_nonce = masking_nonce
        self.masked_response = masked_response

    def serialize(self):
        return self.data + self.masking_nonce + self.masked_response

    def __str__(self):
        return f"CredentialResponse(data={self.data.hex()}, masking_nonce={self.masking_nonce.hex()}, masked_response={self.masked_response.hex()})"
