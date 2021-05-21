import re
from typing import Tuple
import random
import string
import os
import hashlib
import binascii
import hmac
import json
import uuid
import getpass

#load userdata
#userid is users id used to find users information
def display_user(userid: str):
    data = ""
    updated = ""
    try:
        f = open('userdata.json')
        data = json.load(f)
        for i in data['userdata']:
            if str(i['id']) == userid:
                data = i
        f.close()
    except:
        print("failed to find userdata")
    
    if data:
        print("\nUser information")
        print("Name: " + data['name'])
        print("Age: " + data['age'])
        print("Sex: " + data['sex'])
        print("Address: " + data['address'])
        print("Email: " + data['email'] +"\n")

        if sanitized("yn","Do you want to update user information y/n?: ") == "y":
            try:
                updated = update_userdata(data)
            except:
                print("failed to update")

        if updated:
            try:
                f = open('userdata.json', "r")
                data = json.load(f)
                f.close()
                for i in data['userdata']:
                    if str(i['id']) == userid:
                        i['name'] = updated['name']
                        i['sex'] = updated['sex']
                        i['age'] = updated['age']
                        i['address'] = updated['address']
                        i['email'] = updated['email']

                        f = open('userdata.json', "w")
                        json.dump(data,f,indent=4,sort_keys=True)
                        f.close()

                        display_user(userid)
            except:
                print("failed to update userdata to json")
    
#update user information in json
#takes in userdata
#return updated userdata
def update_userdata(olddata):
    if sanitized("yn","Update name y/n?: ") == "y":
        olddata['name'] = sanitized("text","Enter fullname: ")

    if sanitized("yn","Update age y/n?: ") == "y":
        olddata['age'] = sanitized("number","Enter age: ")

    if sanitized("yn","Update sex y/n?: ") == "y":
        olddata['sex'] = sanitized("text","Enter sex: ")

    if sanitized("yn","Update address y/n?: ") == "y":
        olddata['address'] = sanitized("text","Enter full address: ")

    if sanitized("yn","Update email y/n?: ") == "y":
        olddata['email'] = sanitized("email","Enter email: ")

    return olddata

#login to account
#checks if user exist
def log_in():

    i = 0
    triedUserName = {}
    tooMany = False

    while True:
        username = sanitized("usr","Enter Username: ")
        password = sanitized("pass","Enter Password: ")

        userid = authenticate(username,password)
        if userid:
            display_user(userid) 
            break

        amount = 0
        try:
            amount = triedUserName.get(username)
            triedUserName[username] = amount + 1
        except:
            triedUserName[username] = 1
        try:
            for user, value in triedUserName.items():
                if int(value) >= 3:
                    tooMany = True
        except:
            print("failed to check for failure")

        if tooMany:
            print("Too many failures to log in to selected account, terminating system")
            return True
        elif sanitized("yn","Do you want to try again y/n?: ") == "y":
            continue
        break     
    return False  

#Creates new account
#checks if username is available
def sign_in():
    
    while True:
        username = ""
        username = sanitized("usr","Enter Username: ")
        try:     
            availibity = check_availibity(username)
        except:
            print("failed to check availibity")

        if not availibity:
            print("Username invalid or taken")
            continue
        else:
            break
    
    while True:
        password = ""
        password2 = ""
        if sanitized("yn","Do you want system to generate new password for you y/n?: ") == "y":
            generatedPass = generate_password()
            print("generated password: " + generatedPass)
            password = generatedPass
        else:
            print("Password nees to be 8-50 characters in length and contain at least one uppercase, lowercase, number and special character")
            password = sanitized("pass","Enter Password: ")
        password2 = sanitized("pass","Type Password again: ")

        if password == password2:
            break
        else:
            print("Passwords dont match eachother, try again")
            continue
    
    hashedPass = hash_password(password)

    name = sanitized("text","Enter fullname: ")
    age = sanitized("number","Enter age: ")
    sex = sanitized("text","Enter sex: ")
    address = sanitized("text","Enter full address: ")
    email = sanitized("email","Enter email: ")
    userid = str(uuid.uuid4())

    user = {'id': userid, 'username':username, 'password':hashedPass}
    userd = {'id': userid, 'name': name, 'sex': sex, 'age': age, 'address':address, 'email': email}

    try:
        write_to_json(user,'users.json')
    except:
        print("Failed to save to json")
    
    try:
        write_to_json(userd,'userdata.json')
    except:
        print("Failed to save to json")

#generate password
def generate_password():
    while True:
        length = random.randrange(25,50)
        letters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(letters) for i in range(length))
        value = re.sub('[^a-zA-Z0-9,.!@-]',random.choice(string.ascii_letters),password)
        print(value)
        if re.search('[a-z]',value) is None:
            continue
        elif re.search('[\.\-\,\!\@]',value) is None:
            continue
        elif re.search('[A-Z]',value) is None:
            continue
        elif re.search('[0-9]',value) is None:
            continue

        break

    return value

#adds data to json file
def write_to_json(d, filename):  

    with open(filename) as json_file:
        data = json.load(json_file)

    if filename == "users.json":
        temp = data['users']
    elif filename == "userdata.json":
        temp = data['userdata']
    
    try:
        temp.append(d)
    except:
        print("failed to append")

    with open(filename,'w') as f:
        try:
            json.dump(data, f, indent=4)
        except:
            print("failed to dump")

#checks availibity of username from users.json
#returns true if available
def check_availibity(value):

    f = open('users.json')
    data = json.load(f)
    for i in data['users']:
        if i['username'] == value:
            f.close()
            data = ""
            return False
    f.close()
    data = ""
    return True

#check if password matches username
#returns id if match
def authenticate(username: str, password: str):

    userid = ""

    with open('users.json') as json_file:
        data = json.load(json_file)

    for i in data['users']:
        if i['username'] == username:
            userid = i['id']
            stored_password = i['password']
    data = ""
    try:
        if verify_password(stored_password,password):
            return userid
    except:
        userid = ""
        print("password or username was wrong")
        return userid

# hashes password using sha256
# returns salt and hashed password
def hash_password(password):

    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), 
                                salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')

#authenticate pasword
#returns bool
def verify_password(stored_password, provided_password):

    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', 
                                  provided_password.encode('utf-8'), 
                                  salt.encode('ascii'), 
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password

#sanitazition function
#enum
def sanitized(sanType: str,msg: str):

    value = ""
    data = ""
    try:
        if sanType == "yn":
            while True:
                data = input(msg)
                if len(data) >= 5:
                    data[:5]
                data = data.lower()
                value = re.sub('[^yn]','*',data)
                data = ""
                if value == "":
                    continue

                if '*' not in value:
                    break
                else:
                    print('invalid answer, press y or n')
                    continue

        elif sanType == "usr":
            while True:
                data = input(msg)
                if len(data) >= 51:
                    data[:51]
                value = re.sub('[^a-zA-Z0-9]','*',data)
                data = ""
                if value == "":
                    continue
                if '*' not in value:
                    break
                else:
                    print('invalid username, use only characters and numbers')
                    continue

        elif sanType == "pass":
            while True:
                try:
                    data = getpass.getpass(prompt=msg,stream=None)
                except:
                    print("Password failed")
                    continue
                if len(data) >= 51:
                    data[:51]
                    print('Password is too long. Password length should be between 8 and 50')
                    continue
                if len(data) <= 7:
                    print('Password is too short. Password length should be between 8 and 50')
                
                value = re.sub('[^a-zA-Z0-9,.!@-]','*',data)
                data = ""

                if re.search('[a-z]',value) is None:
                    print("Password nees to be 8-50 characters in length and contain at least one uppercase, lowercase, number and special character")
                    continue
                elif re.search('[\.\-\,\!\@]',value) is None:
                    print("Password nees to be 8-50 characters in length and contain at least one uppercase, lowercase, number and special character")
                    continue
                elif re.search('[A-Z]',value) is None:
                    print("Password nees to be 8-50 characters in length and contain at least one uppercase, lowercase, number and special character")
                    continue
                elif re.search('[0-9]',value) is None:
                    print("Password nees to be 8-50 characters in length and contain at least one uppercase, lowercase, number and special character")
                    continue

                if '*' not in value:
                    break
                else:
                    print('invalid password, use only characters, numbers and (!.,-@) these special characters')
                    continue

        elif sanType == "text":
            while True:
                data = input(msg)
                if len(data) >= 101:
                    data[:101]
                value = re.sub('[^[^a-zA-Z0-9,.!@-]+( [^a-zA-Z0-9,.!@-]+)*$]','*',data)
                data = ""
                if value == "":
                    continue                
                if '*' not in value:
                    break
                else:
                    print('use only characters, numbers and (!.,-@) these special characters')
                    continue

        elif sanType == "number":
            while True:
                data = input(msg)
                if len(data) >= 5:
                    data[:5]
                value = re.sub('[^0-9]','*',data)
                data = ""
                if value == "":
                    continue                
                if '*' not in value:
                    break
                else:
                    print('use only numbers.')
                    continue

        elif sanType == "email":
            while True:
                data = input(msg)
                if len(data) >= 101:
                    data[:101]
                value = re.sub('[^a-zA-Z0-9,.!@-]','*',data)
                data = ""
                if len(value.split("@")) != 2:
                    print("Invalid email, Try again")
                    continue 
                if value == "":
                    continue                
                if '*' not in value:
                    break
                else:
                    print('use only characters, numbers and (!.,-@) these special characters')
                    continue
    except:
        print("ops wrong argument given for fucntion")
    return value
    

def main():
    while True:
        # create new user
        if sanitized("yn","New user y/n:  ") == "y":
            sign_in()
    
        # login as old user
        if sanitized("yn","Log in y/n: ") == "y":
            terminated = log_in()
            if terminated:
                break
        if sanitized("yn","Shut down y/n: ") == "y":
            break
        continue

    
main()