from fastapi import APIRouter, status, HTTPException

from .auth import auth
from .bufferoverflow import buffer_overflow
from .certsign import certsign
from .demo import demo

routes = APIRouter()

routes.include_router(auth)
routes.include_router(buffer_overflow)
routes.include_router(certsign)
routes.include_router(demo)

@routes.get("/{path:path}")
def routes_catch():
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Endpoint not Found",
    )