import sys
import os
import platform

if(platform.system()=="Windows"):
    dir_path = os.path.dirname(os.path.realpath(__file__)).split('\\')
    sys.path.insert(1, "\\".join(dir_path[:-1:]))
elif(platform.system()=="Linux"):
    dir_path = os.path.dirname(os.path.realpath(__file__)).split('/')
    print("/".join(dir_path[:-1:]))
    sys.path.insert(1, "/".join(dir_path[:-1:]))

from pypenlib import scanner as SCAN

def testLocalIPgetter():
    return SCAN.IPUtils().get_local_IP()=="10.100.102.88"

def testExternalIPgetter():
    return SCAN.IPUtils().get_external_IP()=="10.100.102.1"

def testPingScan():
    return [SCAN.PINGSCAN().scan("8.8.8.8",False) == "8.8.8.8:Host-Alive", SCAN.PINGSCAN().scan("8.14.23.8",False) != "8.14.23.8:Host-Alive"]

xyePytest = [testLocalIPgetter, testExternalIPgetter, testPingScan]

print("\n".join([f"Test {k+1} : {v()}" for k,v in enumerate(xyePytest)])) # ебychiй pytest не работает с root правами