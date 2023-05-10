from typing import Union

from jose import JWTError
from fastapi import Depends, Request, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.exceptions import HTTPException
from authentication import Authenticate, AccessToken

from config import Config


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = AccessToken.decode(token)
        username: Union[str, None] = payload.get("sub")

        if username is None:
            raise credentials_exception
        
    except JWTError as e:
        raise credentials_exception from e
    
    user = Authenticate.get_user(username)
    if user is not None:
        return user

    raise credentials_exception


async def get_config() -> Config:
    return Config()

async def route_enabled(request: Request, config: Config = Depends(get_config)) -> None:
    route_disabled_exception = HTTPException(
        status_code=status.HTTP_423_LOCKED,
        detail="Endpoint not active",
        headers={"WWW-Authenticate": "Bearer"},
    )

    route = request.url.path.split("/")[1]

    if route in config.enabled_routes:
        return True
    
    raise route_disabled_exception