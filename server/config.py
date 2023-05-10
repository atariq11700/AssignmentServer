from pydantic import BaseSettings
from typing import Optional


class Config(BaseSettings):
    secret_key: str
    enabled_routes: list
    host: str
    port: int
    ssl_keyfile_path: Optional[str]
    ssl_certfile_path: Optional[str]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

