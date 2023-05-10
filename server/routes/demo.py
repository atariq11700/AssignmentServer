import base64

from fastapi import APIRouter, Depends, Form

from server.dependencies import route_enabled
from server.models import User, Answer
from server.dependencies import get_current_user

from apps.demo.cats import URL, get_cat_fact


demo = APIRouter(
    prefix="/demo", 
    tags=["Demo Endpoints"], 
    dependencies=[Depends(route_enabled)]
)

@demo.post("/question", response_model=Answer)
def question(question: str = Form(), user: User = Depends(get_current_user)):
    answer = f"{question} Sorry, {user.first_name}, I don't know, bute here's something that may help. {get_cat_fact()}"
    encoded_answer = base64.b64encode(answer.encode())

    return Answer(
        answer=answer,
        encoded=encoded_answer,
        credit=URL
    )


