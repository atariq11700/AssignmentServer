from fastapi import APIRouter, Depends, Form

from server.models import Answer, Signature, Certificate, Chain, User
from server.dependencies import get_current_user, route_enabled

from apps.certsign import sign_doc, create_cert,get_cert_chain,get_root_cert

certsign = APIRouter(
    prefix="/certsign", 
    tags=["Certificate Assignment"],
    dependencies=[Depends(route_enabled)]
)

@certsign.post("/sign", response_model=Signature)
def get_signed_doc(doc: str = Form(), current_user: User = Depends(get_current_user)):
    return sign_doc(current_user, doc)

@certsign.post("/cert", response_model=Certificate)
def get_certificate(key: str = Form(), current_user: User = Depends(get_current_user)):
    return create_cert(current_user, key)

@certsign.get("/chain", response_model=Chain, dependencies=[Depends(get_current_user)])
def get_cert_chain():
    return get_cert_chain()

@certsign.get("/rootcert", response_model=Certificate, dependencies=[Depends(get_current_user)])
def get_root_cert():
    return get_root_cert()