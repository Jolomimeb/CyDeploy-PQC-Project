import json
from dilithium_py.ml_dsa import ML_DSA_65
from datetime import datetime, timedelta, timezone

#simulates the intermediate CA issuing a leaf certificate given the name and ML-DSA public key
def issue_leaf_certificate(common_name, public_key):
    try:
        #only time the intermediate CA's private key is used: signing the certificate information
        with open("intermediate_private_key.txt", "r") as file:
            intermediate_private_key = bytes.fromhex(file.read())

        #issuer is the intermediate's name
        with open("intermediate_CA.txt", "r") as file:
            intermediate_CA = json.loads(file.read())

        issuer = intermediate_CA["Common_Name"]

        leaf_CA = {
            "Common_Name" : common_name,
            "Issuer" : issuer,
            "Public_Key" : public_key.hex(),
            "Signature" : ML_DSA_65.sign(intermediate_private_key, common_name.encode() + issuer.encode() + public_key).hex(),
            "Expiration_Date" : (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()     #expires 1 year from issue
        }
        return json.dumps(leaf_CA)
    
    except Exception as e:
        print(f"Error: {e}\nCould not create leaf certificate.")

#simulates the server verifying that the leaf was issued by the intermediate, then verifies that the intermediate was issued by the root. Checks if any CAs in the chain are expired
def verify_leaf_certificate(leaf_CA):
    try:
        leaf_CA = json.loads(leaf_CA)

        with open("root_CA.txt", "r") as file:
            root_CA = json.loads(file.read())

        with open("intermediate_CA.txt", "r") as file:
            intermediate_CA = json.loads(file.read())
        
        date_now = datetime.now(timezone.utc)     #current date and time used to check expiration date
        if leaf_CA["Issuer"] == intermediate_CA["Common_Name"] and date_now < datetime.fromisoformat(leaf_CA["Expiration_Date"]) and date_now < datetime.fromisoformat(leaf_CA["Expiration_Date"]):

            issued_by_intermediate = ML_DSA_65.verify(bytes.fromhex(intermediate_CA["Public_Key"]), leaf_CA["Common_Name"].encode() + leaf_CA["Issuer"].encode() + bytes.fromhex(leaf_CA["Public_Key"]), bytes.fromhex(leaf_CA["Signature"]))

            if issued_by_intermediate and intermediate_CA["Issuer"] == root_CA["Common_Name"] and date_now < datetime.fromisoformat(root_CA["Expiration_Date"]):
                issued_by_root = ML_DSA_65.verify(bytes.fromhex(root_CA["Public_Key"]), intermediate_CA["Common_Name"].encode() + intermediate_CA["Issuer"].encode() + bytes.fromhex(intermediate_CA["Public_Key"]), bytes.fromhex(intermediate_CA["Signature"]))
                return issued_by_root
            else:
                return False
            
        else:
            return False
        
    except Exception:
        return False

#returns public key in bytes from json formatted certificate
def get_public_key(certificate):
    certificate = json.loads(certificate)
    return bytes.fromhex(certificate["Public_Key"])