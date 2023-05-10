import time
import random
import json
import base64

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from server.models import User, Certificate, Chain, CertificateBody, Signature
from apps.demo.cats import get_cat_fact

from .documents import SERVER_ISSUER_ID

CERT_BUNDLE_MIN_INDEX = 0
CERT_BUNDLE_MAX_INDEX = 199

BASE_PATH = "apps/certsign/owners/"
BUNDLE_PATH = BASE_PATH + "bundles/"
KEY_PATH = BASE_PATH + "keys/"


def create_cert(user: User, key: str) -> Certificate:
    expiry = time.time() + random.randint(60, 250) * 3600

    cert_body = CertificateBody(
        key=key,
        subject_id=user.username,
        subject=user.first_name,
        issuer_id=SERVER_ISSUER_ID,
        issuer="CS4460",
        good_until=expiry
    )

    private_key = None
    with open("apps/certsign/rootca/root-privkey.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    encoded_doc = json.dumps(cert_body.dict()).encode()
    signature = private_key.sign(
        encoded_doc,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return Certificate(cert=
        "-----BEGIN CERT-----\n" + \
        base64.b64encode(
            json.dumps(
                Signature(
                    data=encoded_doc.decode(),
                    signature=base64.b64encode(signature).decode()
                ).dict()
            ).encode()
        ).decode() + \
        "\n-----END CERT-----\n"
    )
    

def get_cert_chain() -> Chain:
    cert_chain_index = random.randint(CERT_BUNDLE_MIN_INDEX, CERT_BUNDLE_MAX_INDEX)

    signer_id = None
    with open(BASE_PATH + "cert_struct.txt", mode="r") as cert_file:
        all_structs = cert_file.readlines()
        signer_id = all_structs[cert_chain_index].strip().split(":")[-1]
        signer_id = int(signer_id)


    signer_data = None
    with open(BASE_PATH + "owner_info.txt", mode="r") as owner_file:
        signer_data = owner_file.readlines()[signer_id].strip().split(":")

    # Doc that will be signed
    doc = {
        'doc': "Seriously, believe me. " + get_cat_fact(),
        'subject_id': 9035768,
        'subject': 'Walt Disney',
        'issuer_id': signer_data[1],
        'issuer': signer_data[0],
        'padding': 'PSS',
        'hash': 'SHA256'
    }

    signer_priv_key = None
    with open(KEY_PATH + f"{signer_data[0]}-privkey.pem", mode="r") as key_file:
        signer_priv_key = serialization.load_pem_private_key(
            key_file.read().encode(),
            password=None
        )

    encoded_doc = json.dumps(doc).encode()

    signature = signer_priv_key.sign(
        encoded_doc,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    bundle = None
    with open(BUNDLE_PATH + f"bundle-{cert_chain_index}.crt", mode="r") as bundle_file:
        bundle = bundle_file.read()

    return Chain(
        data=encoded_doc.decode(),
        cert_chain=bundle,
        signature=base64.b64encode(signature)
    )

def get_root_cert() -> Certificate:
    with open("apps/certsign/rootca/root-cert.crt", "r") as root_file:
        cert = root_file.read()

    return Certificate(
        cert=cert
    )

