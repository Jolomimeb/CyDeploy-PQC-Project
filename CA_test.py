import datetime
from dilithium_py.ml_dsa import ML_DSA_65
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

root_public_key, root_private_key =  ML_DSA_65.keygen()

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Maryland"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Baltimore"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Organization"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Fake Root CA"),
])

root_cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    root_public_key
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    # Our certificate will be valid for ~10 years
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*10)
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None),
    critical=True,
).add_extension(
    x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    ),
    critical=True,
).add_extension(
    x509.SubjectKeyIdentifier.from_public_key(root_public_key),
    critical=False,
).sign(root_private_key, hashes.SHA256())