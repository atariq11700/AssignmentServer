import os
from datetime import datetime, timedelta
from typing import Union, Optional

import bcrypt
from jose import jwt

from server.models import User
from server.config import Config

class Authenticate:
    FILENAME = f"{os.getcwd()}/accounts/passwd"

    @staticmethod
    def add_user(first_name: str, username: str, password: str) -> None:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        with open(Authenticate.FILENAME, 'a') as auth_file:
            auth_file.write(f"{username}:{first_name}:{password_hash}\n")

    @staticmethod
    def delete_user(username: str) -> None:
        with open(Authenticate.FILENAME, mode="r+") as auth_file:
            lines = auth_file.readlines()
            index = 0
            for i,line in enumerate(lines):
                _username, firstname, password_hash = line.split(":")
                if _username == username:
                    index = i
                    break
            else:
                return
            
            lines.pop(index)
            auth_file.seek(0)
            auth_file.truncate()
            auth_file.writelines(lines)




    @staticmethod
    def get_user(username: str) -> Union[User, None]:
        user: Union[User, None] = None

        with open(Authenticate.FILENAME, 'r') as auth_file:
            for line in auth_file.readlines():
                _username, first_name, hashed_password = line.strip().split(":")
                tmp_user = User(username=_username,first_name=first_name,hashed_password=hashed_password)
                if tmp_user.username == username:
                    user = tmp_user
                    break

        return user

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    
    @staticmethod
    def authenticate_user(username: str, password: str) -> bool:
        user = Authenticate.get_user(username)

        if user is not None and Authenticate.verify_password(password, user.hashed_password):
            return user
        return None
    
class AccessToken:
    ACCESS_TOKEN_EXPIRE_MINUTES = 60
    ALGORITHM = "HS256"

    @staticmethod
    def encode(data: dict, expires_delta: Optional[timedelta] = None, config: Config = Config()) -> str:
        to_encode = data.copy()

        if expires_delta is not None:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=AccessToken.ACCESS_TOKEN_EXPIRE_MINUTES
            )

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(
            to_encode, config.secret_key, algorithm=AccessToken.ALGORITHM
        )

        return encoded_jwt
    
    @staticmethod
    def decode(token: str, config: Config = Config()):
        return jwt.decode(token, config.secret_key, algorithms=[AccessToken.ALGORITHM])
