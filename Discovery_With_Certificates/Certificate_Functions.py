import json
from filelock import FileLock
from dilithium_py.ml_dsa import ML_DSA_65

#simulates the intermediate CA issuing a leaf certificate given the name and ML-DSA public key
def issue_leaf_certificate(common_name, public_key):

    #only time the intermediate CA's private key is used: signing the certificate information
    with FileLock("intermediate_private_key.txt.lock"):
        with open("intermediate_private_key.txt", "r") as file:
            intermediate_private_key = bytes.fromhex(file.read())

    #issuer is the intermediate's name
    with FileLock("intermediate_CA.txt.lock"):
        with open("intermediate_CA.txt", "r") as file:
            intermediate_CA = json.loads(file.read())

    issuer = intermediate_CA["Common_Name"]

    leaf_CA = {
        "Common_Name" : common_name,
        "Issuer" : issuer,
        "Public_Key" : public_key.hex(),
        "Signature" : ML_DSA_65.sign(intermediate_private_key, common_name.encode() + issuer.encode() + public_key).hex()
    }
    return json.dumps(leaf_CA)

#simulates the server verifying that the leaf was issued by the intermediate, then verifies that the intermediate was issued by the root
def verify_leaf_certificate(leaf_CA):
    leaf_CA = json.loads(leaf_CA)

    with open("root_CA.txt", "r") as file:
        root_CA = json.loads(file.read())

    with open("intermediate_CA.txt", "r") as file:
        intermediate_CA = json.loads(file.read())
    
    if leaf_CA["Issuer"] == intermediate_CA["Common_Name"]:
        issued_by_intermediate = ML_DSA_65.verify(bytes.fromhex(intermediate_CA["Public_Key"]), leaf_CA["Common_Name"].encode() + leaf_CA["Issuer"].encode() + bytes.fromhex(leaf_CA["Public_Key"]), bytes.fromhex(leaf_CA["Signature"]))
        if issued_by_intermediate and intermediate_CA["Issuer"] == root_CA["Common_Name"]:
            issued_by_root = ML_DSA_65.verify(bytes.fromhex(root_CA["Public_Key"]), intermediate_CA["Common_Name"].encode() + intermediate_CA["Issuer"].encode() + bytes.fromhex(intermediate_CA["Public_Key"]), bytes.fromhex(intermediate_CA["Signature"]))
            return issued_by_root
        else:
            print("internmediate failed chungus")
            return False
    else:
        print("leaf and intermediate name not match chungus")
        return False

#returns public key in bytes from json formatted certificate
def get_public_key(certificate):
    certificate = json.loads(certificate)
    return bytes.fromhex(certificate["Public_Key"])