from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from server.models import Token
from server.authentication import Authenticate,AccessToken

auth = APIRouter(prefix="/auth", tags=["Authorization"])

@auth.post("/login", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = Authenticate.authenticate_user(form_data.username, form_data.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return {
        "access_token": AccessToken.encode(data={
            "sub" : user.username
        }), 
        "token_type": "bearer"
    }