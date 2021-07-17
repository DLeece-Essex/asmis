#!/usr/bin/env python


import bcrypt, sys, string, random, json

# A basic prep script to make the data needed for the prototype.
# Prompt for each user's input creds, save the output to a text file that can be pasted into the prototype


def newpassword(passwdstr):
    salt=bcrypt.gensalt()
    passwdbytes=bytes(passwdstr,'utf-8')
    passwdhash=bcrypt.hashpw(passwdbytes,salt)
    # use decode to convert to string for storage
    passwdhashstr = passwdhash.decode()
    return passwdhashstr

def testpasswd(pwdstr,pwdhashstr):
    print(pwdhashstr)
    passwdbytes=bytes(pwdstr,'utf-8')
    pwdhash=bytes(pwdhashstr,'utf-8')
    result=bcrypt.checkpw(passwdbytes,pwdhash)

    return result

def newrecord(uname,pwd,contact,role,recdict):
    #tempdict= dict()
    datalist = [pwd,contact,role]
    recdict[uname]=datalist
    return recdict

def tesuserdata(recdict):
    nextrecord=True
    if sys.stdin.isatty():
        while nextrecord:
            print("Checking passwords")
            username = input("Username: ")
            password = input("Password: ")
            pwdhashstr=recdict[username][0]
            if testpasswd(password,pwdhashstr):
                print("the password for " + username + " is " + password)
                nextrecord = input("test another account? True/False")
            else:
                print("that is not the password")
                nextrecord = input("test another password? True/False")
    return

        

def getuserdata():
    nextrecord="yes"
    recdict=dict()
    if sys.stdin.isatty():
        while nextrecord == "yes":
            print("Follow the prompts to create new user data.")
            username = input("Username: ")
            password = input("Password: ")
            passwordhashstr=newpassword(password)
            smscontact=input("SMS contact number:")
            rbacrole=input("Role, 1:user,2:mos,3:it")
            thisrecord=newrecord(username,passwordhashstr,smscontact,rbacrole,recdict)
            print(thisrecord)
            nextrecord = input("Add another record? yes/no")
    return recdict

def storeuserdata(recdict):
    with open ('user_data.txt','w') as fh:
        json.dump(recdict,fh)
    return



    

if __name__ == "__main__":
    thisrecset=getuserdata() 
    # Save data to a file
    storeuserdata(thisrecset)
    tesuserdata(thisrecset)
