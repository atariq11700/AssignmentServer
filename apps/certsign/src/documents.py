import random
import json
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from server.models import Signature, User, Document



SERVER_ISSUER_ID = 8675309

def sign_doc(user: User, msg) -> Signature:
    doc = Document(
        doc=msg,
        subject_id=user.username,
        subject=user.first_name,
        issuer_id=SERVER_ISSUER_ID,
        issuer="CS4460"
    )

    private_key = None
    if random.randint(1,4) == 4:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    else:
        with open("apps/certsign/rootca/root-privkey.pem", mode="rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

    encoded_doc = json.dumps(doc.dict()).encode()

    signature = private_key.sign(
        encoded_doc,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return Signature(
        data=encoded_doc.decode(),
        signature=base64.b64encode(signature)
    )