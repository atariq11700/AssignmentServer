# Assignment Server
This is a linux server to create api endpoints for interacting with python applications. It was designed for educational purposes, where each python application would contain logic for an assignment.

# Organization  
* *accounts/* - contains student account info
    * **student_list.csv** - contains student information used to build the accounts. Format is `<lastname>,<firstname>,<username>,<password>`
    * **passwd** - generated file for server authentication
    * **linux_account_setup_file.txt** - generated file for creating system accounts
* *apps/* - contains the main logic for each "app"(assignment)
    * *setuputils/* - contains the class for creating the setup scripts for each app
        * **menu.py** - contains the classes `Menu` and `MenuOption`
    * *\<appdirs>* - app directories
* server/ - contains the server code
    * **authentication.py** - authentication code
    * **config.py** - pydantic config object for using .env files
    * **dependencies.py** - async python functions for use with fastapi's Depends
        * `get_current_user`
        * `get_config`
        * `route_enabled`
    * **main.py** - server startup code
    * **models.py** - pydantic objects for input/output of the api
    * *ssl/* - contains the server certs and keys for https
    * *routes/* - contains the api endpoints
        * **auth.py** - login endpoint
        * **\<route files>** - python route files for different api endpoints

# Setup/Configuration
1. Create a python virtual environment
2. Install the dependencies from `requirements.txt`
3. Generate a secret key with the below command and assign `SECRET_KEY` to it in `.env`  
    ```bash
    $ openssl rand -hex 32
    ```
4. Set the host by assigning an ipv4 string literal to `host` in `.env`  

    EXAMPLE
    ```txt
    host="127.0.0.1"
    ```
5. Set the port by assigning a port number to `port` in `.env` 

    EXAMPLE
    ```txt
    port=8080
    ```
6. (OPTIONAL)Set the keyfiles and certfiles for the server by setting the path to the files to `ssl_keyfile_path` and `ssl_certfile_path` in `.env` respectively

    EXAMPLE
    ```txt
    ssl_keyfile_path="./server/ssl/privkey.pem"  
    ssl_certfile_path="./server/ssl/certfile.cer"
    ```
7. Enable/Disaple endpoints by adding/removing string literals of the endpoint path in the `enabled_routes` list in `.env`
    * Examples
        * `enabled_routes=["demo","bufferoverflow", "certsign"]`
            * demo, bufferoverflow,and certsign are all enabled
        * `enabled_routes=["demo"]`
            * only demo is enabled
    * the string literal must match the endpoint prefix exactly without the leading forward slash
        ```python
        buffer_overflow = APIRouter(
            prefix="/bufferoverflow", 
            tags=["Buffer Overflow Assignment"],
            dependencies=[Depends(route_enabled)]
        )
        ```
8. run `python3 setup.py` in the root directory(dir containing accounts/,server/,apps/) and run any appropriate setup options

# Running
1. run `sudo ./run.sh` from the root directory

# Adding New Apps/Assignments
1. Make a new directory in the `apps/` directory
    * Write all the source code for your app here
2. Add an `__init__.py` in your app directory
3. Add a `setup.py` to your app directory
    * In `setup.py`, import `Menu` and `MenuOption` from `apps.setuputils`
    * This file is where you will create and write any setup scripts for your app
    * Export the scripts by creating a variable named `setup_menu` at the end of the file, of type `Menu` and add all your scripts to the menu
4. Add api routes to your app by creating a new python file in `server/routes/<appname>.py`
    * Add a fastapi `APIRouter` and add all your endpoints to that router. 
    * Import and add your router to the main server routes in `server/routes/__init__.py`

# Documentation
This readme and readme's in each app directory