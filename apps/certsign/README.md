# Certsign
This is the source code for a certificate app. The goal is to experience working with certificates, RSA public/private keys, digital signature, and verification. (I didn't modify this assignment much from the original)

# Organization
* *owners/* - contains data for certificate chains
    * *bundles/* - contains the actual generated certificate chains
    * *keys/* - contains the generated RSA pub/priv keys used to make the certificates
    * **cert_struct.txt** - contains the certifcates used and ordering to create each certificate chain in *bundles/*
    * **owner_info** - contains information about "owners". Used to make key pairs and certificate chains
* *rootca/* - contains the certsign root authority keys and certificate
* *src/* - source code 
    * **certificates.py** - logic for interacting with certificates
    * **documents.py** - logic for interacting with digital documents
* **setup.py** - contains the setup scripts(I didn't touch these almost at all from the original implementation)