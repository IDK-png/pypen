import sys
import os

dir_path = os.path.dirname(os.path.realpath(__file__)).split('\\')
dir_path.pop()
dir_path = "\\".join(dir_path)
sys.path.insert(1, dir_path)

from pypenlib import scanner as SCAN

def testLocalIPgetter():
    assert SCAN.IPUtils().get_local_IP()=="10.100.102.1"

def testExternalIPgetter():
    assert SCAN.IPUtils().get_external_IP()=="10.100.102.88"

def testPingScan():
    assert SCAN.PINGSCAN().scan("8.8.8.8",False) == "8.8.8.8:Host-Alive"
    assert SCAN.PINGSCAN().scan("8.14.23.8",False) != "8.14.23.8:Host-Alive"

SCAN.TCPSCAN("8.8.8.8").scan(5,52,56)