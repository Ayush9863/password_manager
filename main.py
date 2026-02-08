from cryptography.fernet import Fernet
import hashlib
import os
from playsound3 import playsound

# Encryption key generate karo (ek baar)
# key = Fernet.generate_key()
# with open("key.key","wb") as f:
#     f.write(key)

def load_key():
    with open("key.key", "rb") as f:
        return f.read()                   

key=load_key()
fer=Fernet(key)   

def set_master_password():
    master_pwd=input("what is the master password")
    hashed = hashlib.sha256(master_pwd.encode()).hexdigest()
    with open("master.key", "w") as f:
        f.write(hashed)
    print("Master password set successfully 🔐")

def verify_master_password():
    if not os.path.exists("master.key"):
        set_master_password()
    with open("master.key", "r") as f:
        saved_hash = f.read()

    attempts = 3
    while attempts > 0:
        master_pwd = input("Enter master password: ")
        hashed = hashlib.sha256(master_pwd.encode()).hexdigest()

        if hashed == saved_hash:
            print("Access granted \n")
            playsound("success.mp3")
            return True
        else:
            attempts -= 1
            print(f"Wrong password  | Attempts left: {attempts}")
            playsound("error.mp3")

    print("Too many wrong attempts. Program locked.")
    return False


def view():
    with open("passwords.txt","r") as f:
        for line in f.readlines():
            data=line.strip()
            user,passw=data.split("|")
            print("User:",user,"|Password:",fer.decrypt(passw.encode()).decode())
       
def add():
    name=input("Account Name:")
    pwd=input("password:")
    with open("passwords.txt","a") as f:
         f.write(name+"|"+fer.encrypt(pwd.encode()).decode()+"\n")

def delete():
    name = input("Account name to delete: ")
    lines = []
    found = False
    with open("passwords.txt", "r") as f:
        lines = f.readlines()
    with open("passwords.txt", "w") as f:
        for line in lines:
            if name + "|" not in line:
                f.write(line)
            else:
                found = True
    if found:
        print(f"{name} deleted successfully")
    else:
        print("Not found")         

# .encode() → string ➜ bytes
# .decode() → bytes ➜ string
# Python me Fernet (encryption) only bytes accept karta hai, isliye convert karna padta hai.         

if not verify_master_password():
    exit()
while True:
    mode = input("would you like to add a new password or view existing ones or delete ones(view,add,delete),press q to quit").lower()
    if mode=="q":
        break
    if mode=="view":
       view()
    elif mode=="add":
        add()
    elif mode=="delete":
        delete()    