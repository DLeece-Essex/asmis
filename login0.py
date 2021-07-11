#!/usr/bin/env python
# use stdiomask for better password UI experience
import sys,socket,stdiomask, random, string



def getip():
    # use an RFC 1918 address, plant fake address if only loop back found
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('10.255.255.255',1))
    ip=s.getsockname()[0]
    if ip.startswith('127.'):
        ip='1.2.3.4'
    return ip


def newsessionid():
    sessionid=''.join(random.choice(string,string.ascii_letters + string.digits,k=24))
    return sessionid


def checkusername(uname,sid):
    failedlogins=getfailedlogincount(sid)
    if failedlogins > 5:
        print("Likley Malicious, reject session")
        return
    else:
        print("Check whitelisted characters in this username {}".format(uname))
    return


def getcredentials(thissession):
    # only works via command line, warn & exit
    if sys.stdin.isatty():
        print("Welcome to ASMIS, please enter your username and password")
        username = raw_input("Username: ")
        password = stdiomask.getpass(prompt='Password: ', mask='*')
        checkusername(username,thissession)
    else:
        print("This does not appear to be a command line interface")
    # Check the username for malicious content prior to testing for password
    # return a tuple 
    return (username,password)


def newlogin():
    # This function simulates 
    thissession=newsessionid()
    thisip=getip() # cant really use this yet
    failcount=0
    # update tracking
    updatesessiontracker(thissession,failcount)
    return thissession

def updatesessiontracker(sid,fc):
    # track failures by session if
    if sid in sessiontracker.keys():
        previousfailures = sessiontracker['sid']
        failedlogincount= sessiontracker['sid'] = previousfailures + 1
    else:
        sessiontracker['sid']=fc
        failedlogincount= sessiontracker['sid']
    return failedlogincount


def getfailedlogincount(sessionid):
    return sessiontracker['sessionid']


if __name__ == "__main__":
    # track active sessions for failed logins
    global sessiontracker
    sessiontracker = dict()
    # set up the first login, simulates a new HTTP connection from a client device
    thissession = newlogin()

    results=getcredentials(thissession)
    print(results)

