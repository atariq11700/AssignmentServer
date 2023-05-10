import pkgutil
import importlib
from apps.setuputils import Menu, MenuOption
from server.authentication import Authenticate
import os
from tqdm import tqdm

def main():
    setup_menu = Menu("Main Setup")
    setup_menu.add_option(MenuOption("(Sudo)Disable ASLR", disable_aslr))
    setup_menu.add_option(MenuOption("(Sudo)Create student accounts and directories", gen_student_dirs_and_accounts))
    setup_menu.add_option(MenuOption("(Sudo)Delete student accounts and directories", remove_student_dirs_and_accounts))

    for app_loader, app_name, app_is_pkg in pkgutil.iter_modules(["apps/"]):
        for loader, module_name, is_pkg in pkgutil.iter_modules([f"apps/{app_name}/"]):
            if module_name == "setup":
                _module = importlib.import_module(f"apps.{app_name}.setup")
                _menu = getattr(_module, "setup_menu")
                assert isinstance(_menu, Menu)

                setup_menu.add_option(MenuOption(str(_menu), _menu.show))

    setup_menu.show()

def disable_aslr():
    os.system("sudo sysctl -w kernel.randomize_va_space=0")

########################
# Run this to create the login accounts file
# Run $sudo newusers linux_account_setup_file.txt
#   to create the accounts
# Each entry of the input file should be of the format
#   Last,First,username,password
#   Smith,Bob,A01673432,1313535
#   Get this from Canvas
########################
def gen_student_dirs_and_accounts():
    reading_file = open("accounts/student_list.csv", "r")
    writing_file = open("accounts/linux_account_setup_file.txt", "w")

    lines = reading_file.readlines()
    iter = tqdm(lines)
    iter.set_description("Creating new users file")
    for line in iter:
        lastname, firstname, username, password = line.strip().split(",")
        user_line = f"{username}:{password}:::{firstname} {lastname},,,:/home/{username}:/bin/bash"
        writing_file.write(user_line + "\n")

        Authenticate.add_user(firstname, username, password)

    reading_file.close()
    writing_file.close()

    os.system("sudo newusers accounts/linux_account_setup_file.txt")

    dirs = os.listdir("/home")

    student_dirs = list(filter(lambda dir_name: dir_name.lower().startswith("a") and dir_name[1:].isnumeric(), dirs))
    iter = tqdm(student_dirs)
    iter.set_description("Changing student directory permissions")

    for student_dir in iter:
        os.system(f"sudo chmod +rwx,g-rwx,o-rwx /home/{student_dir}")

def remove_student_dirs_and_accounts():
    acc_file = open("accounts/student_list.csv", mode="r")
    lines = acc_file.readlines()
    iter = tqdm(lines)

    for line in iter:
        lastname, firstname, username, password = line.strip().split(",")

        os.system(f"sudo pkill -U {username}")
        os.system(f"sudo userdel -f -r {username}")

        Authenticate.delete_user(username)

    acc_file.close()


main()