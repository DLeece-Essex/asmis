#!/usr/bin/env python
# use stdiomask for better password UI experience
import sys,socket,stdiomask, random, string, datetime, bcrypt,  time, random
from cryptography.fernet import Fernet

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
recordsdictionary={\
    "bsmith": ["$2b$12$Me7cJkoqN0ya8Jh6NQOqHeDWlZ55xzffxQu5VOUPiNZ1OqekBKKUi", "gAAAAABg81k4KZcGxf4waRbGonV0QDcRwXVRba-QDP-5Y205sm2zfg23GPfnecLmyzLQeOiypP0MgsY5CBpqThIDanSVdo9BAA==", "1"],\
        "wchandy": ["$2b$12$caHEQ4FGG41DGYcT8z5NYe9deowfJhmeCdhqFYiMVLMGb5BbHsWFq", "gAAAAABg81l3ILWRjuPd7zPY48A9qT_k86VKAV0A7GKIIjsCOLKKailUhH_2tExtm_9h51agyreIE02bTSqLGfoyQ45tdWEglQ==", "2"],\
            "svaughan": ["$2b$12$S1w.O3swC4Ipaab2EnEOS.UFknDqMrVD2DnuTY4abiwrrM39j8Hai", "gAAAAABg81maMxJOfackasxS7YJUM7XaqGWyHLIrU1Arub1IiRDaNCH29ihm01eeC4eNNCZtAb_622flPDGv-QjKdF4v-1BrRw==", "4"],\
                "mrebennack": ["$2b$12$hBiwTstfHRD17Cc.aJstGeJmLxpiUyOdAk59lAbOGCicuUGNKzy9K", "gAAAAABg81nZhyKUcJa2DsSNo1DqRLRdddOMtVA3fVL-KN0w4iCGGakffDBpT36qzKhiesKN8kEV9szmB5k1jNB3e3kbTKVyAw==", "3"],\
                    "bbking": ["$2b$12$hdkOAoFWZEIXR.wCHeT7h.8BJD139Z8Uc2LYCXlfylNznu4LZvyvO", "gAAAAABg81n9oHQL5SQwU1tXpPjikVC6qKgm0ol7Y_DQ6GHbQdS-1N5YVeDodEXk1OzRdVu9CcRsV3VBaOtvocnW_yeuUzsASQ==", "1"]\
                        }
#####################################################
# Encryption Key - do not store with data!          #
# wKbWNb-hGe1OY-lqGaL3rGoCsStK45i3Wwfb9TQ_CfA=      #
#####################################################


# Network Security related functions
# Global threat IP reputation list ( add local RFC 1918  address of test machine to validate)
ipreputationlist=["202.192.34.106","138.197.141.172","121.74.25.77","49.233.155.23","45.227.255.204","221.131.165.56","211.219.29.107","115.79.200.221","72.94.165.10","40.88.4.73","34.89.123.155","185.202.1.175","180.106.148.221","162.243.102.191","107.182.17.174","95.140.118.44","141.98.10.179","34.71.20.225","81.68.184.218","74.94.31.141","197.237.174.178","51.158.107.168","45.146.165.72","211.252.87.42","203.151.39.4","61.177.173.30","222.186.30.112","116.87.198.111","182.23.23.42","180.76.105.122","155.133.11.242","206.130.141.138","189.173.133.18","188.166.22.79","168.196.96.37","3.10.227.68","203.20.148.87","42.193.110.250","161.35.112.155","140.250.55.53","107.189.30.250","107.155.15.62","210.72.91.6","172.105.254.10","159.65.149.54","49.232.221.113","31.154.169.242","177.10.105.143","167.71.170.179"]

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


# Encryption related functions
def getsecrets():
    message=("Control 3: Retrieving application data decryption key from Secrets Manager application" )
    controldisplay(message)
    # key provided for simulation only, actual application must always retrieve keys, no storage in source code 
    keylist=[b'wKbWNb-hGe1OY-lqGaL3rGoCsStK45i3Wwfb9TQ_CfA=','wKbWNb-hGe1OY-lqGaL3rGoCsStK45i3Wwfb9TQ_CfA=']
    return keylist

def decryptdata(key,datastr):
    data=bytes(datastr,'utf-8')
    decryptor=Fernet(key)
    clearbytes=decryptor.decrypt(data)
    # return byte array as a string
    return clearbytes.decode()

# Security monitoring functions
def newsessionid():
    sessionid=''.join(random.choices(string.ascii_letters + string.digits,k=24))
    return sessionid

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

# Application security related functions
def testusername(uname,sessionid):
    failedlogins=getfailedlogincount(sessionid)
    if failedlogins > 5:
        newsuspiciousactivity(sessionid,uname)
    else:
        charwhitelist=set(string.ascii_letters + string.digits + "'"+".")
        #print("Control 1: Confirm only whitelisted characters are in the following username {}".format(uname))
        message="Control 1: Confirm only whitelisted characters are in the following username {}".format(uname)
        controldisplay(message)
        # Use set compression just like list, break test into two parts to make code easier to follow  
        badchars={c for c in uname if c not in charwhitelist}
        if badchars:
            updatesessiontracker(sessionid)
            return False
    return True

def testpassword(username,password):
    try:
        pwdhashstr= recordsdictionary[username][0]
        passwdbytes=bytes(password,'utf-8')
        pwdhash=bytes(pwdhashstr,'utf-8')
        result=bcrypt.checkpw(passwdbytes,pwdhash)
    except KeyError:
        return False
    return result

def getsmscontact(username,key):
    message="Control 3.1: Decrypting user contact information"
    controldisplay(message)
    enccontact=recordsdictionary[username][1]
    smscontact=decryptdata(key,enccontact)
    return smscontact

def newsmsmessage(smscontact):
    # Generate a 6 digit random number
    mfacode=random.randint(100000,999999)
    message("Sending six digit code {} to contact number {} via SMS".format(mfacode,smscontact))
    controldisplay(message)
    return mfacode


# program flow functions
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
        message='Control 2: checking if password is valid'
        controldisplay(message)
        validpassword = testpassword(username,password)
        if validpassword:
            return [True,username]
        else:
            updatesessiontracker(thissession)  # track failed password login attempts 
    # return false by default, only convert to true when valid uname & pwd
    return [False,username]

def newlogin():
    # This function simulates the initial connection from an external source to HTTP server
    thissession=newsessionid()
    # collect on initial connection for testing against global threat lists
    thisip=getip()
    testsourceip(thisip) 
    # update tracking if not blocked by global list
    updatesessiontracker(thissession)
    return (thissession,thisip)

def controldisplay(message):
    print("\n--------------Control Check---------------------------")
    time.sleep(1)
    print(message)
    for count in range(3):
        print("...........")
        time.sleep(count)
    print("\n")
    return


if __name__ == "__main__":
    # track active sessions for failed logins
    global sessiontracker
    sessiontracker = dict()
    # set up the first login, simulates a new HTTP connection from a client device
    thissession,thisip = newlogin()   # session ID is the only reliable way to track individula users
    message= "Control 0: check this IP against global TI lists: " + thisip
    controldisplay(message)
    #print("check this IP against global TI lists: " + thisip)
    validlogin=False
    while not validlogin:
        validlogin=getcredentials(thissession)
        if validlogin[0]:
            # To retrieve the SMS contact associated with the valid username it must be decrypted 
            keylist=getsecrets()
            smscontact=getsmscontact(validlogin[1],keylist[1])

            print("now validate via MFA")
            message="Control 4: Multifactor authentication using stored data for useraccount {} ".format(validlogin[1])
            controldisplay(message)
            mfacode=newsmsmessage(smscontact)
            # Start a while loop and wait for 120 seconds, if no match exi t, write failed MFA login to log
            
            
        else:
            failedlogincount=getfailedlogincount(thissession)
            print("Invalid user name or password")
            print("You have " + str(7 - failedlogincount) + " attempts remaining")