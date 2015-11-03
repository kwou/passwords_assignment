import hashlib
import sys

def main():
    pw_offset = 75779 # 0x12803
    filename = "54724117.program2.exe"
    
    old_pw = input('Enter old password: ')
    h = get_hash(old_pw)

    f = open(filename, 'rb+')
    f.seek(pw_offset)
    stored_pw = f.read(20);
    f.close()

    if h != stored_pw:
        print("Password does not match!")
    else:
        new_pw = input('Enter new password: ')
        new_pw_confirm = input('Confirm password: ')

        if new_pw != new_pw_confirm:
            print("Passwords do not match!")
        else:            
            new_hash = get_hash(new_pw)
            f = open(filename, 'rb+')
            f.seek(pw_offset)
            f.write(new_hash)
            f.close()
            print ("Password Changed!")

def get_hash(str):
    sh = hashlib.sha1()
    sh.update(str.encode('utf-8'))
    return sh.digest()

if __name__ == "__main__":
    main()
