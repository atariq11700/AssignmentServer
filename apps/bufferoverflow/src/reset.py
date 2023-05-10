import os
import shutil
import random
import pwd
import stat
import time

from datetime import timezone, timedelta, datetime
from server.models import User, Confirm

VICTIM_USERNAME = "newt"

APP_PATH = "apps/bufferoverflow"
BIN_PATH = f"{APP_PATH}/out/bin"
SHELLCODE_PATH = f"{APP_PATH}/out/shellcode"

RESULTS_PATH = f"{APP_PATH}/results"

BINARY_NAME = "prog"
SHELLCODE_NAME = "shellcode.bin"

TIMEZONE_OFFSET = -6.0  # Mountain Daylight Time (UTC−06:00)
TZINFO = timezone(timedelta(hours=TIMEZONE_OFFSET))


binaries = os.listdir(BIN_PATH)
shellcodes = os.listdir(SHELLCODE_PATH)

assert len(binaries) == len(shellcodes), f"Different number of binaries and shellcodes, {len(binaries)}, {len(shellcodes)}"

def reset_user(current_user: User) -> Confirm:
    if check_cookie(current_user.username):
        return Confirm(result="Please exit out of all instances of a newt shell or prog or gdb before trying to reset.")

    file_index = random.randint(0, len(binaries) - 1)
    copy_shellcode(current_user.username, file_index)
    copy_binary(current_user.username, file_index)
    reset_secret(current_user, file_index)

    return Confirm(result="Your account as been reset. You  may try again")

def check_cookie(username: str) -> bool:
    return ".assn5_cookie" in os.listdir(f"/home/{username}")


def reset_secret(user: User, index: int) -> None:
    secret_path = f"/home/{user.username}/secret/"
    try:
        shutil.rmtree(secret_path)
    except Exception as e:
        pass

    os.mkdir(secret_path, mode=stat.S_IRWXU)
    os.chown(secret_path, pwd.getpwnam(VICTIM_USERNAME).pw_uid, pwd.getpwnam(VICTIM_USERNAME).pw_gid)

    shutil.copy(f"{APP_PATH}/out/success/{user.username}-success", f"{secret_path}/success")
    os.chmod(f"{secret_path}/success", mode = stat.S_IXOTH | stat.S_IXGRP | stat.S_IXUSR)

    start_time = time.time_ns() 
    record_reset(user, index, start_time)


def copy_binary(username: str, index: int) -> None:
    bin_path = f"/home/{username}/{BINARY_NAME}"
    bin_file = binaries[index]
    shutil.copy(f"{BIN_PATH}/{bin_file}", bin_path)
    os.chown(bin_path, pwd.getpwnam("root").pw_uid, pwd.getpwnam("root").pw_gid)
    os.chmod(bin_path, mode=stat.S_ISUID | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IROTH)



def copy_shellcode(username: str, index: int) -> None:
    shellcode_path = f"/home/{username}/{SHELLCODE_NAME}"
    shellcode_file = shellcodes[index]
    shutil.copy(f"{SHELLCODE_PATH}/{shellcode_file}", shellcode_path)
    os.chmod(shellcode_path, mode=stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

def record_reset(user: User, index: int, start_time: int) -> None:
    check_and_make_dirs()
    with open(f"{RESULTS_PATH}/{user.first_name}-{user.username}.txt", mode="a") as results_file:
        results_file.write(f"RESET,{datetime.now(TZINFO)},{index},{binaries[index]},{shellcodes[index]},{start_time},0\n")

def check_and_make_dirs():
    if "results" not in os.listdir(APP_PATH):
        os.mkdir(RESULTS_PATH)