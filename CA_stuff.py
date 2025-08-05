import Certificate_Functions, secrets
from dilithium_py.ml_dsa import ML_DSA_65

pk, sk = ML_DSA_65.keygen()

leaf_CA = Certificate_Functions.issue_leaf_certificate("Device1",  pk)

leaf_CA_encoded = leaf_CA.encode()
leaf_CA_decoded = leaf_CA_encoded.decode()

print(Certificate_Functions.verify_leaf_certificate(leaf_CA_decoded))
iv = secrets.token_bytes(32)
print(iv)

tuple = (1,2,3)

element2, element3 = tuple[1], tuple[2]

print(element2)
print(element3)