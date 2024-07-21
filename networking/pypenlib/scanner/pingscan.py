from scapy.all import *
from pypenlib.scanner.iputils import IPUtils
import sys
import io
class PINGSCAN:
    def __init__(instance):
        '''The function initializes a configuration setting to disable all print statements in Scapy.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `__init__` method refers to the instance of the class itself.
        '''
        conf.verb = 0 # Вырубает нахуй все принты ебучего Scapy

    def scan(instance, dstIP, printOut=True):
        '''This Python function sends an ICMP echo request to a destination IP address and prints whether the
        host is alive or not based on the response.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `__init__` method refers to the instance of the class itself.
            It's not used in this method, because there is no class parameters.
        dstIP
            The `dstIP` parameter in the `scan` function represents the destination IP address that you want to
            scan for connectivity. This function sends an ICMP echo request to the specified destination IP
            address and waits for a response. If a response is received (echo-reply), it indicates that the host
            is alive, else, host is down.
        printOut, optional
            The `printOut` parameter in the `scan` function is a boolean parameter that determines whether the
            function should print the scan results to the console or not.
        
        Returns
        -------
            The `scan` function will return a string indicating whether the host at the specified `dstIP` is
            alive or not responding. The format of the return value will be `"{dstIP}:Host-Alive"` if the host
            is alive, and `"{dstIP}:Host-Not-Responding"` if the host is not responding.
        
        '''
        ans, unans = sr(IP(dst=dstIP,ttl=(1,20))/ICMP(id=1,seq=1), timeout=1) # Обычный ICMP пакет
        #_____________________________ЧТЕНИЯ ОТВЕТА_____________________________
        capture = io.StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        print(f"{ans.summary()}")
        sys.stdout = save_stdout
        #_______________________________________________________________________
        if "echo-reply" in capture.getvalue():
            if(printOut):
                print(f"{dstIP}:Host-Alive")
            return f"{dstIP}:Host-Alive"
        else:
            if(printOut):
                print(f"{dstIP}:Host-Not-Responding")
            return f"{dstIP}:Host-Not-Responding"