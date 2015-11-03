import hashlib
import sys

def main():
    pw_offset = 75779 # 0x12803 - offset of hashed password in file
    filename = "54724117.program2.exe"
    
    new_pw = input('Enter new password: ')
    new_pw_confirm = input('Confirm password: ')

    # Ensure the two entered passwords matched before changing
    if new_pw != new_pw_confirm:
        print("Passwords do not match!")
    elif len(new_pw) == 0:
        print("Password must be longer than 0 characters!")
    else:
        # Set the new password
        new_hash = get_sha1_hash(new_pw)
        f = open(filename, 'rb+')
        f.seek(pw_offset)
        f.write(new_hash)
        f.close()
        print ("Password Changed!")

def get_sha1_hash(str):
    sh = hashlib.sha1()
    sh.update(str.encode('utf-8'))
    return sh.digest()

if __name__ == "__main__":
    main()
