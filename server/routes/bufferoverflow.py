from fastapi import APIRouter, Depends, Form

from server.models import User, Confirm
from server.dependencies import get_current_user, route_enabled

from apps.bufferoverflow import reset_user
from apps.bufferoverflow import submit_result

buffer_overflow = APIRouter(
    prefix="/bufferoverflow", 
    tags=["Buffer Overflow Assignment"],
    dependencies=[Depends(route_enabled)]
)

####### Reset the users account to try a new buffer overflow ########
@buffer_overflow.post("/reset", response_model=Confirm)
def reset_server(current_user: User = Depends(get_current_user)):
    return reset_user(current_user)

####### Question API used for figuring things out ########
@buffer_overflow.post("/submit", response_model=Confirm)
def submit_success(ticket: str = Form(), current_user: User = Depends(get_current_user)):
    return submit_result(current_user, ticket)
