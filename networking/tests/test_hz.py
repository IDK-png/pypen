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

x = SCAN.TCPSCAN("8.8.8.8", ttlCount=10)
x.scan(10,startPort=53,endPort=81)