from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def public_private_keygen():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return public_key, private_key

#Serializes X25519 public key object to bytes so can be transmitted through sockets
def serialize_public_key(public_key):
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return serialized_public_key

#Takes serialized X21229 public key, reverts it back to X25519 public key object, generates secret with that and private key, and derives a secret with specified length
def derive_secret(received_serialized_public_key, your_private_key, key_length_bytes):
    received_public_key = x25519.X25519PublicKey.from_public_bytes(received_serialized_public_key)
    secret = your_private_key.exchange(received_public_key)
    derived_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length_bytes,
        salt=None,
        info=None
    ).derive(secret)
    return derived_secret