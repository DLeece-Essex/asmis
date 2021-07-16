#!/usr/bin/env python


import bcrypt, sys, string, random, json

# A basic prep script to make the data needed for the prototype.
# Prompt for each user's input creds, save the output to a text file that can be pasted into the prototype


def newpassword(passwdstr):
    salt=bcrypt.gensalt()
    passwdbytes=bytes(passwdstr,'utf-8')
    passwdhash=bcrypt.hashpw(passwdbytes,salt)
    return passwdhash

def testpasswd(pwdstr,pwdhash):
    print(pwdhash)
    result=bcrypt.checkpw(pwdstr,pwdhash)

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
            pwdhash=recdict[username][0]
            passwdbytes=bytes(password,'utf-8')
            if testpasswd(password,pwdhash):
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
            passwordhash=newpassword(password)
            smscontact=input("SMS contact number:")
            rbacrole=input("Role, 1:user,2:mos,3:it")
            thisrecord=newrecord(username,passwordhash,smscontact,rbacrole,recdict)
            print(thisrecord)
            nextrecord = input("Add another record? yes/no")
    return recdict


    

if __name__ == "__main__":
    thisrecset=getuserdata()
    tesuserdata(thisrecset)
