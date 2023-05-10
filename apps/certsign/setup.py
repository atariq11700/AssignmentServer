from apps.setuputils import Menu, MenuOption
from random import randint, shuffle
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import json
from time import time
from random import choices, shuffle

APP_PATH = "apps/certsign"
KEY_PATH = f"{APP_PATH}/owners/keys"
BUNDLE_PATH = f"{APP_PATH}/owners/bundles"



#######################
# List of names who will be config of keys
#######################
owner_list = ["Ariel", "Baloo", "Coco", "Dewey", "Elsa", "Flounder", "Goofy", "Hercules", "Isabela", "Jafar",
              "Kanga", "Lilo", "Maui", "Nala", "Olaf", "Piglet", "Quasimodo", "Rex", "Stella", "Timon"]



#######################
# Create the server keys and certificate
#######################
def gen_root_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(f"{APP_PATH}/rootca/root-privkey.pem", 'wb') as f:
        f.write(priv_pem)
        f.close()

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{APP_PATH}/rootca/root-pubkey.pem", 'wb') as f:
        f.write(pub_pem)
        f.close()

####################
# owner_list is the list of config in the following format
# name$
#
# generates an owner_info file which includes an id# and a flag
# if the owner should have an expired certificate
####################
def make_owner_info():
    with open(f"{APP_PATH}/owners/owner_info.txt", 'w') as g:
        # Choose some config to have expired certificates or be an imposter
        # 0 - normal
        # 1 - expired
        # 2 - bad key
        owner_count = len(owner_list)
        expired_count = int(owner_count * .20) # 20% have an expired certificate
        imposter_count = int(owner_count * .15) # 15% are imposters with bad keys
        good_count = owner_count - expired_count - imposter_count # 65% are good
        option_list = [0] * (good_count + 1) + [1] * expired_count + [2] * imposter_count
        shuffle(option_list)

        for name in owner_list:
            new_line = name + ":"
            new_line += str(randint(10000, 99999)) + ":"
            new_line += str(option_list.pop()) + "\n"
            g.write(new_line)

        g.close()


####################
# Generates the public and private keys for all owners
###################
def key_gen():
    with open(f"{APP_PATH}/owners/owner_info.txt", 'r') as f:
        for line in f.readlines():
            name = line.split(":")
            create_keys(name[0])

        f.close()

####################
# Actual key generation for a given name
# Stores keys as name-privkey.pem and name-pubkey.pem
###################
def create_keys(name):

    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open(f"{KEY_PATH}/{name}-privkey.pem", 'w') as f:
        f.write(priv_pem.decode())
        f.close()

    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{KEY_PATH}/{name}-pubkey.pem", 'w') as f:
        f.write(pub_pem.decode())
        f.close()

####################
# Reads and prints the public key for an owner
###################
def read_key(name):
    with open(f"{KEY_PATH}/{name}-pubkey.pem", "r") as key_file:
        pub_key = serialization.load_pem_public_key(
            key_file.read()
        )
        key_file.close()

        print(pub_key)

####################
# Create the structure of the certificate chains
# Represented as
# <chainId>:<ownerOrdinalId>:<ownderOrdinalId> etc.
###################
def create_cert_struct(num, min, max):
    with open(f"{APP_PATH}/owners/cert_struct.txt", 'w') as f:
        for i in range(num):
            cert_string = str(i)
            id_list = list(range(len(owner_list)))
            shuffle(id_list)
            for j in range(randint(min, max)):
                if cert_string.count(":") == max: # already has max because of a self signed
                    break
                cert_string += ":" + str(id_list[j])
                if randint(0, 19) == 1: # self signed cert will happen if True
                    print("Self Signed!")
                    cert_string += ":" + str(id_list[j])
            cert_string += "\n"
            f.write(cert_string)
        f.close()

####################
# Create a certificate based on a signer and subject
# Returns a string encoded JSON object
###################
def create_cert(signer, subject):
    expiry = time()
    if subject.get('option') == '1':
        expiry -= randint(1, 200) * 86400 # subtract some random number of days
    else:
        expiry += randint(60, 250) * 86400 # add some random number of days

    signed_doc = {
        'key': subject.get('public-key'),
        'subject_id': subject.get('id'),
        'subject': subject.get('name'),
        'issuer_id': signer.get('id'),
        'issuer': signer.get('name'),
        'good_until': expiry,
        'padding': 'PSS',
        'hash': 'SHA256'
    }

    signer_key = signer.get('priv-key')
    if signer.get('option') == '2':
        signer_key = rsa.generate_private_key( # get a random key if option 2
            public_exponent=65537,
            key_size=2048,
        )
        signed_doc['issuer_id'] = 'BAD'

    encoded_doc = json.dumps(signed_doc).encode() # need to sign a byte form

    signature = signer_key.sign(
        encoded_doc,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    cert_body = json.dumps({
        "data": encoded_doc.decode(),
        "signature": base64.b64encode(signature).decode()
    })

    cert = "-----BEGIN CERT-----\n"
    cert += base64.b64encode(cert_body.encode()).decode()
    cert += "\n-----END CERT-----\n"

    return cert

####################
# Create the actual certificate chains.
# The file name is as follows
# bundle-<idNum>.cert
# the idNum corresponds to the sequence in the struct file
###################
def create_cert_bundles():
    owners = []
    with open(f"{APP_PATH}/owners/owner_info.txt", 'r') as owner_file:
        for line in owner_file.readlines():
            owners.append(line.strip().split(":"))
        owner_file.close()

    cert_struct_list = []
    with open(f"{APP_PATH}/owners/cert_struct.txt", 'r') as f:
        for line in f.readlines():
            cert_struct_list.append(line.strip().split(":"))
        f.close()

    for cert_struct in cert_struct_list:
        cert_bundle = []
        for i in range(len(cert_struct)):
            if i == 0:
                # add the root certificate - self signed
                pass
            elif i == 1:
                subject = {
                    'id': owners[int(cert_struct[i])][1],
                    'name': owners[int(cert_struct[i])][0],
                    'option': owners[int(cert_struct[i])][2]
                }
                with open(f"{KEY_PATH}/{owners[int(cert_struct[i])][0]}-pubkey.pem", "r") as key_file:
                    public_key = key_file.read()
                    key_file.close()
                subject['public-key'] = public_key

                signer = {
                    'id': 8675309,
                    'name': 'CS4460',
                }
                with open(f"{APP_PATH}/rootca/root-privkey.pem", "r") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read().encode(),
                        password=None
                    )
                    key_file.close()
                signer['priv-key'] = private_key

                cert = create_cert(signer, subject)

                cert_bundle.append(cert)
            else:
                subject = {
                    'id': owners[int(cert_struct[i])][1],
                    'name': owners[int(cert_struct[i])][0],
                    'option': owners[int(cert_struct[i])][2]
                }
                with open(f"{KEY_PATH}/{owners[int(cert_struct[i])][0]}-pubkey.pem", "r") as key_file:
                    # public_key = serialization.load_pem_public_key( # get the public key to sign
                    #     key_file.read(),
                    # )
                    public_key = key_file.read() # keep public key in byte form
                    key_file.close()
                subject['public-key'] = public_key

                signer = {
                    'id': owners[int(cert_struct[i - 1])][1],
                    'name': owners[int(cert_struct[i - 1])][0],
                    'option': owners[int(cert_struct[i - 1])][2]
                }
                with open(f"{KEY_PATH}/{owners[int(cert_struct[i - 1])][0]}-privkey.pem", "r") as key_file:
                    private_key = serialization.load_pem_private_key(
                        key_file.read().encode(),
                        password=None
                    )
                    key_file.close()
                signer['priv-key'] = private_key

                cert = create_cert(signer, subject)

                cert_bundle.append(cert)

        with open(f"{BUNDLE_PATH}/bundle-{str(cert_struct[0])}.crt", 'w') as cert_file:
            for i in reversed(cert_bundle):
                cert_file.write(i)
            cert_file.close()

def create_root_cert():
    subject = {
        'id': 8675309,
        'name': 'CS4460',
        'option': 0
    }
    with open(f"{APP_PATH}/rootca/root-pubkey.pem", "r") as key_file:
        public_key = key_file.read()
        key_file.close()
    subject['public-key'] = public_key

    signer = {
        'id': 8675309,
        'name': 'CS4460',
        'option': 0
    }
    with open(f"{APP_PATH}/rootca/root-privkey.pem", "r") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read().encode(),
            password=None
        )
        key_file.close()
    signer['priv-key'] = private_key

    cert = create_cert(signer, subject)

    with open(f"{APP_PATH}/rootca/root-cert.crt", 'w') as cert_file:
        cert_file.write(cert)
        cert_file.close()


def setup_fresh():
    gen_root_keys()
    create_root_cert()

    make_owner_info()
    key_gen()
    create_cert_bundles()


setup_menu = Menu("Certsign Setup")
setup_menu.add_option(MenuOption("Generate Server Keys", gen_root_keys))
setup_menu.add_option(MenuOption("Create New Owner Info", make_owner_info))
setup_menu.add_option(MenuOption("Generate Owner Keys", key_gen))
setup_menu.add_option(MenuOption("Create New Owner Certificate Bundles", create_cert_bundles))
setup_menu.add_option(MenuOption("Create New Server(Root CA) Certificate(depends on gen server keys)", create_root_cert))
setup_menu.add_option(MenuOption("Reset all and setup a fresh runtime", setup_fresh))


