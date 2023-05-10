import os
import sys
sys.path.append(os.getcwd())

import uvicorn
from fastapi import FastAPI
from routes import routes

from config import Config


app = FastAPI()
app.include_router(routes)


config = Config()

if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        port=config.port, 
        host=config.host,
        reload=True,
        ssl_keyfile=config.ssl_keyfile_path,
        ssl_certfile=config.ssl_certfile_path
    )
