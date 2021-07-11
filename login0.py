#!/usr/bin/env python
# use stdiomask for better password UI experience
import sys,socket,stdiomask, random, string, datetime



def newsuspiciousactivity(sessionid,uname):
    # Log format, 
    # Timestamp Webserver-Hostname asmisprogram: Multiple failed authentication attemps for <sessionid> from <IP>
    timestamp=datetime.datetime.now().isoformat("T","seconds")
    thisip=getip()
    hostname="web1" # would capture hostname of computer reporting log
    programid="ASMIS_Login[12345]" # would capture program name and PID
    logmessage=timestamp + " " + hostname + " " + programid + ": " + \
            "Multiple failed authentication attempts for {} from IP {} and the following username: {}".format(sessionid,thisip,uname)
    print("You appear to be having trouble logging in, please contact Queens Medical Centre at 1-800-555-1212 for assistance")
    print("Goodbye\n")
    print("------------- Security event monitoring control------------------- ")
    print("The following suspicous active log will be forwared to Queens security monitoring services:")
    print(logmessage)
    exit(1)
    return


def getip():
    # use an RFC 1918 address, plant fake address if only loop back found
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('10.255.255.255',1))
    ip=s.getsockname()[0]
    if ip.startswith('127.'):
        ip='1.2.3.4'
    return ip


def newsessionid():
    sessionid=''.join(random.choices(string.ascii_letters + string.digits,k=24))
    return sessionid

def testusername(uname,sessionid):
    failedlogins=getfailedlogincount(sessionid)
    if failedlogins > 5:
        newsuspiciousactivity(sessionid,uname)
        #print("Likley Malicious, reject session")
        return
    else:
        charwhitelist=set(string.ascii_letters + string.digits + "'"+".")
        print("Control 1: Confirm only whitelisted characters are in the following username {}".format(uname))
        # Use set compression just like list, break test into two parts to make code easier to follow  
        badchars={c for c in uname if c not in charwhitelist}
        if badchars:
            updatesessiontracker(sessionid)
            return False
    return True


def getcredentials(thissession):
    # only works via command line, warn & exit
    if sys.stdin.isatty():
        print("Welcome to ASMIS, please enter your username and password")
        username = input("Username: ")
        password = stdiomask.getpass(prompt='Password: ', mask='*')
        validusername=testusername(username,thissession)
    else:
        print("This does not appear to be a command line interface")
    # Check the username for malicious content prior to testing for password
    if validusername:
        print('Control 2: checking if password is valid')
        return True
        # if failed, second call to updatesessiontracker
    # return false by default, only convert to true when valid uname & pwd
    return False


def newlogin():
    # This function simulates the initial connection from an external source to HTTP server
    thissession=newsessionid()
    # collect on initial connection for testing against global threat lists
    thisip=getip() 
    # update tracking
    updatesessiontracker(thissession)
    return (thissession,thisip)

def updatesessiontracker(sessionid):
    # track login attempts by session
    if sessionid in sessiontracker.keys():
        previousfailures = sessiontracker[sessionid]
        sessiontracker[sessionid] = previousfailures + 1
    else:
        sessiontracker[sessionid]=1
    return


def getfailedlogincount(sessionid):
    return sessiontracker[sessionid]


if __name__ == "__main__":
    # track active sessions for failed logins
    global sessiontracker
    sessiontracker = dict()
    # set up the first login, simulates a new HTTP connection from a client device
    thissession,thisip = newlogin()   # session ID is the only reliable way to track individula users
    print("check this IP against global TI lists: " + thisip)
    validlogin=False
    while not validlogin:
        validlogin=getcredentials(thissession)
        if validlogin:
            print("now validate via MFA")
        else:
            failedlogincount=getfailedlogincount(thissession)
            print("Invalid user name or password")
            print("You have " + str(7 - failedlogincount) + " attempts remaining")

