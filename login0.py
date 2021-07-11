#!/usr/bin/env python
# use stdiomask for better password UI experience
import sys,socket,stdiomask, random, string, datetime

'''
ReadMe:
To enable the entire simulation through a single python script the following data
must be prepopulated in the data structures below. 

User account database records will contain usernames,salted passwords, SMS contact number and application role.
This data would normally reside in multiple tables within a database but can be simulated with a python dictionary

Global threat intellignce services such as reputation list checking are often used to
shun traffic from known malicious sources quickly at the network layer, reducing the 
application load by avoiding needlessly validating untrusted source input data that is
almost certainly intended to attack the system.  
'''

# User account database data


# Global threat IP reputation list ( add local RFC 1918  address of test machine to validate)
ipreputationlist=["202.192.34.106","138.197.141.172","121.74.25.77","49.233.155.23","45.227.255.204","221.131.165.56","211.219.29.107","115.79.200.221","72.94.165.10","40.88.4.73","34.89.123.155","185.202.1.175","180.106.148.221","162.243.102.191","107.182.17.174","95.140.118.44","141.98.10.179","34.71.20.225","81.68.184.218","74.94.31.141","197.237.174.178","51.158.107.168","45.146.165.72","211.252.87.42","203.151.39.4","61.177.173.30","222.186.30.112","116.87.198.111","182.23.23.42","180.76.105.122","155.133.11.242","206.130.141.138","189.173.133.18","188.166.22.79","168.196.96.37","3.10.227.68","203.20.148.87","42.193.110.250","161.35.112.155","140.250.55.53","107.189.30.250","107.155.15.62","210.72.91.6","172.105.254.10","159.65.149.54","49.232.221.113","31.154.169.242","177.10.105.143","167.71.170.179"]





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

def testsourceip(thisip):
    if thisip in ipreputationlist:
        print("WAF termination based on IP reputation list")
        timestamp=datetime.datetime.now().isoformat("T","seconds") 
        hostname="waf1" # would capture hostname of computer reporting log
        programid="wafdaemon[12345]" # would capture program name and PID
        logmessage=timestamp + " " + hostname + " " + programid + ": " + \
            "Msgid 666 (IP reputationlist match) connection dropped from IP {}".format(thisip)
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
    testsourceip(thisip) 
    # update tracking if not blocked by global list
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

