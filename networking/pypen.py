import sys
import pypenlib as pypen

def help_command():
    print("pypen -{scanType} {IP} -{additional}")

scanners = {"ts" : pypen.scanner.TCPSCAN, "us" : pypen.scanner.UDPSCAN, "arp" : pypen.scanner.ARPSCAN}

def PypenConsole():
    print("TEST")

def PypenRunner(string):
    print(string.split("-"))

if __name__ == "__main__":
    if(len(sys.argv)==1):
        PypenConsole()
    else:
        PypenRunner(" ".join(sys.argv))