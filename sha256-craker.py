from pwn import*
import sys

if len(sys.arguv)!=2:
    print("Invalid arguments")
    print(f"<> {sys.arguv[0]} <sha256sum>")
    exit()

wanted_hash=sys.arguv[1]
attempts=0

with log.progress(f"Attemping to crack {wanted_hash}") as p:
    with open("/usr/share/wordlists/rockyou.txt", "r", encoding="latin-1") as password_list:
        for password in password_file:
            password=password.strip("\n").encode("latin-1")
            hash_sum=sha256sumhex(password)
            p.status(f"[{attempts}] {password.decode('latin-1')} == {hash_sum}")
            if hash_sum==wanted_hash:
                p.success(f"Password hash was found after {attempts} attempts!\n{password.decode('latin-1')} => {hash_sum}")
                exit()
            attempts += 1
        p.failure("Password hash not found!")
