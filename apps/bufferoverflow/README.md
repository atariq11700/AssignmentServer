# Buffer Overflow
This is the source code for a buffer overflow app. The goal is to overflow a buffer using `strcpy` and get a reverse shell with given shellcode. When the program is compromised, a user will have the UID of user `newt` and will be able to cd and run a token generating executable to submit to the server for points.

# Organization
* *out/* - generated binaries and shellcodes needed for the app
* *results/* - contains the reset and submissions log for each user 
* *src/* - source code
    * **baseshellcode.bin** - reverse shell shellcode
    * **reset.py** - code for reseting a user directory with new versions of the program and shellcode
    * **submit.py** - code for submitting a ticket
    * **vulnerable.c** - buffer overflow program source code
    * *success/* - source for the ticket generating program
        * *libtommath/* - c math library [https://github.com/libtom/libtommath](https://github.com/libtom/libtommath)
        * *libtomcrypt/* - c cryptography library [https://github.com/libtom/libtomcrypt](https://github.com/libtom/libtomcrypt)
        * **privkey.der** - generated rsa private key in DER format for decrypting a ticket
        * **pubkey.der** - generated rsa public key in DER format for encrypting a ticket
        * **success.c** - source code for generating a ticket
* **setup.py** - setup scripts

# Building
All the scripts should already be made in `setup.py` but here are some just in case
* Building the buffer overflow program
    * `gcc -DBUFFER_SIZE=<buffer size(int)> <path to vulnerable.c>/vulnerable.c -z execstack -fno-stack-protector -m64 -O0 -o <output path and name>`
* Building libtommath
    * cd into the cloned repo
    * `make`
* Building libtomcrypt
    * cd into the cloned repo
    * `make CFLAGS='-DUSE_LTM -DLTM_DESC -I../libtommath/' EXTRALIBS='../libtommath/libtommath.a`
* Building the ticket generating program
    * `<key>` should be a hex string of the rsa public key in der format
    * `<key length>` should be the length(int) of the hex string of the key
    * `<username>` should be a string of an username
    * `gcc <path to success.c>/success.c <path to libtomcrypt>/libtomcrypt/libtomcrypt.a <path to libtommath>/libtommath/libtommath.a -lm -DKEY="<key>" -DKEYSIZE=<key length> -DUSERNAME="<username>" -o <output path and name>`

# Results Format
`(RESET/PASS),date,randomly_selected_file_index,copied_binary_file_name,copied_shellcode_file_name, time_ns(start time if RESET, if PASS then time since last RESET), score`

# Debugging the buffer over flow program
* You can use gdb like normal however a certain flag must be set
* 2 options to set the flag
    1. `gdb -iex "set follow-fork-mode child" <program>`
    2. `gdb <program>`, then when in the gdb shell first run, `set follow-fork-mode child`