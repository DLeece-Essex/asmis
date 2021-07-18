#!/usr/bin/env python
import time, threading
from threading import Thread, Event

mfacode=123321

def codeprompt(mfacode):
    mfaresponse=0
    while mfaresponse != mfacode:
        try:
            mfaresponse=int(input("MFA code (6 digits): "))
            if mfaresponse==mfacode:
                print('correct mfa code')
                return True
        except ValueError:
            pass
    return False

if __name__ == '__main__':
    mfaprompt_thread = Thread(target=codeprompt(mfacode))
    mfaprompt_thread.start()
    mfaprompt_thread.join(timeout=120)
