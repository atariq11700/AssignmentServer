import os
import random
from tqdm import tqdm
import pwd
import shutil
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from apps.setuputils import Menu, MenuOption

NUMBER_FILES = 200
MAX_SHELLCODE_SIZE = (48 + (12 * 20))
MIN_BUFFER_SIZE = MAX_SHELLCODE_SIZE + 0x100

APP_PATH = "apps/bufferoverflow"

def check_and_make_dirs():
    if "out" not in os.listdir(APP_PATH):
        os.mkdir(f"{APP_PATH}/out")

    if "bin" not in os.listdir(f"{APP_PATH}/out"):
        os.mkdir(f"{APP_PATH}/out/bin")

    if "shellcode" not in os.listdir(f"{APP_PATH}/out"):
        os.mkdir(f"{APP_PATH}/out/shellcode")

    if "success" not in os.listdir(f"{APP_PATH}/out"):
        os.mkdir(f"{APP_PATH}/out/success")

def build_prog():
    try:
        shutil.rmtree(f"{APP_PATH}/out/bin")
    except Exception as e:
        pass

    check_and_make_dirs()
    iter = tqdm(range(NUMBER_FILES))
    iter.set_description("Creating Prog Exectutables")

    for prog_file_index in iter:
        buff_size = random.randint(MIN_BUFFER_SIZE, 4000)
        os.system(f"gcc -DBUFFER_SIZE={buff_size} {APP_PATH}/src/vulnerable.c -o {APP_PATH}/out/bin/prog-{prog_file_index}.elf -z execstack -fno-stack-protector -m64 -O0")

    iter = tqdm(os.listdir(f"{APP_PATH}/out/bin"))
    iter.set_description("Stripping")
    for file in iter:
        os.system(f"strip {APP_PATH}/out/bin/{file}")

def create_shellcodes():
    try:
        shutil.rmtree(f"{APP_PATH}/out/shellcode")
    except Exception as e:
        pass

    check_and_make_dirs()
    #list of indicies in the shellcode that if nops inserted wont break the shellcode
    valid_indicies = [0x3,0x5,0x7,0xa,0x11,0x14,0x18,0x19,0x1c,0x1f,0x20,0x21,0x24,0x26,0x28,0x2a,0x2b,0x2d,0x2e]
    base = list(open(f"{APP_PATH}/src/baseshellcode.bin", mode="rb").read())
    
    iter = tqdm(range(NUMBER_FILES))
    iter.set_description("Creating Shellcodes")

    for shellcode_file_index in iter:
        output = base.copy()
        offset = 0
        for _ in range(12):
            index = valid_indicies[random.randint(0, len(valid_indicies) - 1)] + offset
            nops = random.randint(4,50)
            offset += nops

            pre = output[:index]
            mid = [0x90 for _ in range(nops)]
            post = output[index:]

            output = pre + mid + post
            assert len(output) <= MIN_BUFFER_SIZE, f"Shellcode smaller than min buffer size"

        with open(f"{APP_PATH}/out/shellcode/shellcode-{shellcode_file_index}.bin", mode="wb") as out:
            out.write(bytes(output))

def check_forlibtom():
    if "libtommath" not in os.listdir(f"{APP_PATH}/src/success"):
        print("Plase setup the libtom suite")
        return False
    if "libtomcrypt" not in os.listdir(f"{APP_PATH}/src/success"):
        print("Plase setup the libtom suite")
        return False
    
    return True

def setup_libtom():
    os.system(f"git clone https://github.com/libtom/libtommath.git {APP_PATH}/src/success/libtommath")
    os.system(f"git clone https://github.com/libtom/libtomcrypt.git {APP_PATH}/src/success/libtomcrypt")

    os.system(f"cd {APP_PATH}/src/success/libtommath && make")
    os.system(f"cd {APP_PATH}/src/success/libtomcrypt && make CFLAGS='-DUSE_LTM -DLTM_DESC -I../libtommath/' EXTRALIBS='../libtommath/libtommath.a'")

def gen_rsa():
    privkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
    pubkey = privkey.public_key()

    priv_der = privkey.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_der = pubkey.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"{APP_PATH}/src/success/pubkey.der", 'wb') as f:
        f.write(pub_der)
        f.close()

    with open(f"{APP_PATH}/src/success/privkey.der", 'wb') as f:
        f.write(priv_der)
        f.close()

def build_sucess():
    try:
        shutil.rmtree(f"{APP_PATH}/out/success")
    except Exception as e:
        pass

    check_and_make_dirs()
    if not check_forlibtom():
        return
    
    if "pubkey.der" not in os.listdir(f"{APP_PATH}/src/success/") or "privkey.der" not in os.listdir(f"{APP_PATH}/src/success/"):
        print("Generate rsa keys before building the success programs")
        return
        

    lines = list(map(lambda line: line.split(","), open("accounts/student_list.csv", mode="r").readlines()))

    key = open(f"{APP_PATH}/src/success/pubkey.der", mode="rb").read().hex()
    iter = tqdm(lines)
    iter.set_description("Building Success Executables")

    for lastname, firstname, username, passowrd in iter:
        os.system(f"gcc {APP_PATH}/src/success/success.c {APP_PATH}/src/success/libtomcrypt/libtomcrypt.a {APP_PATH}/src/success/libtommath/libtommath.a -lm -DKEY=\"\\\"{key}\\\"\" -DKEYSIZE={len(key)} -DUSERNAME=\"\\\"{username}\\\"\" -o {APP_PATH}/out/success/{username}-success")

    iter = tqdm(os.listdir(f"{APP_PATH}/out/success/"))
    iter.set_description("Stripping")

    for file in iter:
        os.system(f"strip {APP_PATH}/out/success/{file}")


def setup_fresh():
    try:
        shutil.rmtree(f"{APP_PATH}/out/")
        shutil.rmtree(f"{APP_PATH}/results/")
        
        shutil.rmtree(f"{APP_PATH}/src/success/libtommath")
        shutil.rmtree(f"{APP_PATH}/src/success/libtomcrypt")

        
    except Exception as e:
        pass

    check_and_make_dirs()
    build_prog()
    create_shellcodes()
    gen_rsa()
    setup_libtom()
    build_sucess()


def generate_report():
    try:
        report = open(f"{APP_PATH}/results/report.csv", mode="w")
    except PermissionError as e:
        os.system(f"sudo chown {pwd.getpwuid(os.getuid()).pw_name} {APP_PATH}/results")
        report = open(f"{APP_PATH}/results/report.csv", mode="w")

    report.write(f"firstname,lastname,username,score\n")
    accounts = []
    with open("accounts/student_list.csv", mode="r") as accs:
        accounts = map(lambda l: l.strip().split(","), accs.readlines())

    iter = tqdm(accounts)
    iter.set_description("Generating User Reports")

    for lastname, firstname, username, _ in iter:
        try:
            with open(f"{APP_PATH}/results/{firstname}-{username}.txt") as results:
                lines = results.readlines()
                pass_lines = list(filter(lambda l: l.startswith("PASS"), lines))
                if len(pass_lines) < 1:
                    report.write(f"{firstname} {lastname} {username} score: NO PASSES\n")
                    continue

                passes_split = map(lambda line: line.strip().split(","), pass_lines)
                passes_split = sorted(passes_split, key=lambda line: int(line[-1]), reverse=True)
                last_pass = passes_split[0]

                call_type, date, file_index, bin_file, shellcode_file, time_taken, score = last_pass
                report.write(f"{firstname},{lastname},{username},{score}\n")
        except FileNotFoundError as e:
            pass

    report.close()
    print(f"Report generated at {APP_PATH}/results/report.csv")

setup_menu = Menu("Bufferoverflow Setup")
setup_menu.add_option(MenuOption("Build Prog", build_prog))
setup_menu.add_option(MenuOption("Create Shellcodes", create_shellcodes))
setup_menu.add_option(MenuOption("Setup the libtom suite", setup_libtom))
setup_menu.add_option(MenuOption("Build the success programs(depend on rsa keygen)", build_sucess))
setup_menu.add_option(MenuOption("Create new ticket generation rsa keys(run before build success programes)", gen_rsa))
setup_menu.add_option(MenuOption("Reset all and setup a fresh runtime", setup_fresh))
setup_menu.add_option(MenuOption("Generate a results report", generate_report))