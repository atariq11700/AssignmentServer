from server.models import User, Confirm
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding 
from fastapi import HTTPException, status
from datetime import timezone, timedelta, datetime



APP_PATH = "apps/bufferoverflow"
TIMEZONE_OFFSET = -6.0  # Mountain Daylight Time (UTC−06:00)
TZINFO = timezone(timedelta(hours=TIMEZONE_OFFSET))

key_file = open(f"{APP_PATH}/src/success/privkey.der", mode="rb")
key_bytes = key_file.read()
key_file.close()

private_key = serialization.load_der_private_key(
    key_bytes,
    None,
    default_backend()
)   


def submit_result(user: User, ticket: str) -> Confirm:
    username, end_time_ns = decrypt(ticket).split(":")

    if username != user.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ticket username does not match logged in user"
        )
    
    with open(f"{APP_PATH}/results/{user.first_name}-{user.username}.txt", mode="r+") as results:
        lines = results.readlines()

        last_call = lines[-1]
        call_type, date, fileindex, binary_file, shellcode_file, time_ns, _score = last_call.split(",")

        if call_type != "RESET":
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail="The last api call before submit should be a reset"
            )
        
        ltns = len(time_ns)
        letns = len(end_time_ns)
        resolution_diff = max(ltns, letns) - min(ltns, letns)

        if ltns > letns:
            time_ns = time_ns[:-resolution_diff]
        if letns > ltns:
            end_time_ns = end_time_ns[:-resolution_diff]
        
        time_taken_ns = int(end_time_ns) - int(time_ns)
        msg, val = score(time_taken_ns)
        results.write(f"PASS,{datetime.now(TZINFO)},{fileindex},{binary_file},{shellcode_file},{time_taken_ns},{val}\n")

        return Confirm(
            result=msg
        )
    
def score(time_ns: int) -> "tuple[str, int]":
    time_ms = time_ns // 1000
    time_s = time_ms // 1000000

    out = f"Congratulations!!! You completed your task in {timedelta(microseconds=time_ms)}" 
    if time_s <= 1:
        return out + "That qualifies you for 35 speed points. That's the max possible plus a bonus 10!!!", 35
    elif time_s <= 5:
        return out + "That qualifies you for 25 speed points", 25
    elif time_s <= 30:
        return out + "That qualifies you for 20 speed points", 20
    elif time_s <= 60:
        return out + "That qualifies you for 15 speed points", 15
    elif time_s <= 120:
        return out + "That qualifies you for 10 speed points", 10
    elif time_s <= 360:
        return out + "That qualifies you for 5 speed points", 5
    else:
        return out + "You did not qualify for speed points", 0


def decrypt(b64encoded_ciphertext: str) -> str:
    decoded_ticket = base64.b64decode(b64encoded_ciphertext.encode())
    decrypted_ticket = private_key.decrypt(
        decoded_ticket,
        padding.OAEP(
            padding.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    return decrypted_ticket.decode("utf-8")