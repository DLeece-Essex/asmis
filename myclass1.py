#!/usr/bin/env python

class CallMe(object):
    """An example class:CallMe"""
    version=0.1

def __init__(self,nm='default name'):
    """constructor"""
    self.name=nm
    print('create a class instance for ', nm)

def showname(self):
    print('Your name is ', self.name)

def changename(self,x):
    return x+x

