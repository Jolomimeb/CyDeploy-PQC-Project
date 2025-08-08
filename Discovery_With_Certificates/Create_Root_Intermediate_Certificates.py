import json
from dilithium_py.ml_dsa import ML_DSA_65

root_public_key, root_private_key = ML_DSA_65.keygen()
root_common_name = "Fake Root CA"

#self-signs certificate information with root private key. During signing, names are encoded. Public key and signature fields are in hex for json format
root_CA = {
    "Common_Name" : root_common_name,
    "Public_Key" : root_public_key.hex(),
    "Signature" : ML_DSA_65.sign(root_private_key, root_common_name.encode() + root_public_key).hex()    
}

intermediate_public_key, intermediate_private_key = ML_DSA_65.keygen()
intermediate_common_name = "Fake Intermediate CA"
intermediate_issuer = root_CA["Common_Name"]

#simulated root issuing a intermediate CA and signing it with root's private key
intermediate_CA = {
    "Common_Name" : intermediate_common_name,
    "Issuer": intermediate_issuer,     #identifies root CA that issued intermediate CA
    "Public_Key" : intermediate_public_key.hex(),
    "Signature" : ML_DSA_65.sign(root_private_key, intermediate_common_name.encode() + intermediate_issuer.encode() + intermediate_public_key).hex()
}

with open("root_CA.txt", "w") as file:
    file.write(json.dumps(root_CA))

with open("intermediate_CA.txt", "w") as file:
    file.write(json.dumps(intermediate_CA))

#write intermediate private key to text for use when issuing leaf certificates.
#Wont need to write root private key since it was simulated here issuing the intermediate CA and not needed for this program anymore
with open("intermediate_private_key.txt", "w") as file:
    file.write(intermediate_private_key.hex())

#confirms the intermediate CA was issued by the root by verifying signature with root's public key
print(ML_DSA_65.verify(bytes.fromhex(root_CA["Public_Key"]), intermediate_CA["Common_Name"].encode() + intermediate_CA["Issuer"].encode() + bytes.fromhex(intermediate_CA["Public_Key"]), bytes.fromhex(intermediate_CA["Signature"])))