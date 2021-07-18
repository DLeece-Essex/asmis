#!/usr/bin/env python
import time
from pytimedinput import timedInput

mfacode=123321


def codeprompt(mfacode):
    failcount=0
    while failcount < 6:
        # using third party module for the timer
        mfaresponse,timedOut=timedInput("MFA code (6 digits): ",30,True,6)
        if not timedOut:
            try:
                if int(mfaresponse)==mfacode:
                    print('correct mfa code')
                    return True
                else:
                    print("MFA code incorrect")
                    failcount = failcount + 1
            except ValueError:
                pass
            else:
                print("MFA code incorrect or expired")
                failcount=6    
    return False

if __name__ == '__main__':
    mfaresult=codeprompt(mfacode)
    if mfaresult:
        print("get user's RBAC code")