from scapy.all import *
from pypenlib.scanner.iputils import IPUtils
import requests
class OSSCAN:
    def __init__(instance):
        '''The function initializes a configuration setting to disable all print statements in Scapy.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `__init__` method refers to the instance of the class itself.
        '''
        instance._TTLDICT = {32: ["Windows 95/98/ME"], 64: ["Linux","FreeBSD","Mac OS X"], 128: ["Windows XP/7/8/2003/2008"], 255: ["Solaris"] }
        # Простой лист, потом расширю це хуэту в целую дата базу. подключу нормальный SQL а не эту залупу буду использовать
        conf.verb = 0 # Вырубает нахуй все принты ебучего Scapy

    def TCPTTL(instance, dstIP, printOut=True):
        '''This Python function `TCPTTL` sends a TCP packet with a specified Time-To-Live (TTL) value to a
        destination IP address and then determines the operating system based on the TTL value of the
        response packet.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `TCPTTL` function is an instance of a class or object that contains
            a `_TTLDICT` attribute.
            dstIP
            The `dstIP` parameter in the `TCPTTL` function stands for the destination IP address to which the
            TCP packet will be sent. This IP address is used to send the packet and determine the Time-To-Live
            (TTL) value for the packet.
        printOut, optional
            The `printOut` parameter in the `TCPTTL` function is a boolean parameter that determines whether
            the function should print output or not.
        
        Returns
        -------
            The function `TCPTTL` returns the operating system (OSTTL) based on the TTL value received in
            response to a TCP packet sent to the specified destination IP address.
        
        '''
        ans, _ = sr(IP(dst=dstIP, ttl=255)/TCP(), timeout=5)
        if ans:
            for snd,recv in ans:
                ttlNum = int(recv[IP].ttl);
                print(f"TTL:{ttlNum}")
                OSTTL = min(instance._TTLDICT.keys(), key=lambda x: abs(x - ttlNum))
                if(printOut):
                    print(" ".join(instance._TTLDICT[OSTTL]))
                return instance._TTLDICT[OSTTL]
        else:
            if(printOut):
                print(None)
            return None
        
    def TCPWSIZE(instance, dstIP, printOut=True) -> None:
            pass 
    
    def UDPTTL(instance, dstIP, printOut=True):  
        '''The function `UDPTTL` sends a UDP ping to a destination IP address with a specified TTL value and
        returns the corresponding operating system based on the TTL value.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `UDPTTL` function is an instance of a class or object that contains
            a `_TTLDICT` attribute.
        dstIP
            The `dstIP` parameter in the `UDPTTL` function is the destination IP address to which the UDP
            packet will be sent for testing the Time-To-Live (TTL) value.
        printOut, optional
            The `printOut` parameter in the `UDPTTL` function is a boolean parameter that determines whether
            the function should print output or not.
        
        Returns
        -------
            The function `UDPTTL` returns the operating system (OSTTL) corresponding to the Time-To-Live (TTL)
            value obtained from the response to the UDP ping sent to the destination IP address.
        
        '''
        ans, _ = sr(IP(dst=dstIP, ttl=255)/UDP(dport=15222)/Raw(load="UDP Ping"), timeout=5)
        if ans:
            for snd,recv in ans:
                ttlNum = int(recv[IP].ttl);
                print(f"TTL:{ttlNum}")
                OSTTL = min(instance._TTLDICT.keys(), key=lambda x: abs(x - ttlNum))
                if(printOut):
                    print(" ".join(instance._TTLDICT[OSTTL]))
                return instance._TTLDICT[OSTTL]
        else:
            if(printOut):
                print(None)
            return None 
        
    def ICMPTTL(instance, dstIP, printOut=True) -> None:
        pass
#        ans, unans = sr(IP(dst=dstIP,ttl=255)/ICMP(id=1,seq=1), timeout=1) # Обычный ICMP пакет
#        if ans:
#            for snd,recv in ans:
#                recv.show();
#        else:
#            if(printOut):
#                print(None)
#            return None 