from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str

class Confirm(BaseModel):
    result: str

class User(BaseModel):
    username: str
    first_name: str
    hashed_password: str

class Signature(BaseModel):
    data: str
    signature: str

class Answer(BaseModel):
    answer: str
    encoded: str
    credit: str

class Chain(Signature):
    cert_chain: str

class Certificate(BaseModel):
    cert: str

class Document(BaseModel):
    doc: str
    subject_id: str
    subject: str
    issuer_id: int
    issuer: str
    padding: str = "PSS"
    hash: str = "SHA256"


class CertificateBody(BaseModel):
    key: str
    subject_id: str
    subject: str
    issuer_id: int
    issuer: str
    good_until: float
    padding: str = "PSS"
    hash: str = "SHA256"