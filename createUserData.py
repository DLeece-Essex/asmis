#!/usr/bin/env python

import bcrypt, sys, string, random, json

# A basic prep script to make the data needed for the prototype.
# Prompt for each user's input creds, save the output to a text file that can be pasted into the prototype


def newpassword(passwdstr):
    salt=bcrypt.gensalt()
    passwdbytes=bytes(passwdstr,'utf-8')
    passwdhash=bcrypt.hashpw(passwdbytes,salt)
    return passwdhash


def newrecord(uname,pwd,contact,role):
    tempdict= dict()
    datalist = [pwd,contact,role]
    tempdict[uname]=datalist
    return tempdict


def getuserdata():
    nextrecord=True
    if sys.stdin.isatty():
        while newpassword:
            print("Follow the prompts to create new user data.")
            username = input("Username: ")
            password = input("Password: ")
            passwordhash=newpassword(password)
            smscontact=input("SMS contact number:")
            rbacrole=input("Role, 1:user,2:mos,3:it")
            thisrecord=newrecord(username,passwordhash,smscontact,rbacrole)
            print(thisrecord)
            nextrecord = input("Add another record? True/False ")
    return


        


if __name__ == "__main__":
    getuserdata()