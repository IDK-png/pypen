from scapy.all import *
import threading
import sys
import io
import colorama
from colorama import Fore, Style
from pypenlib.scanner.iputils import IPUtils
class TCPSCAN:
    def __init__(instance, dstIP, hostIP=IPUtils().get_local_IP(), ttlCount=15, timeout=0.5):
        '''This Python function initializes an instance with default values for destination IP, host IP, TTL
        count, and timeout, setting up various attributes for network scanning using Scapy.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `__init__` method refers to the instance of the class itself.
            
        dstIP
            The `dstIP` parameter in the `__init__` method is used to specify the destination IP address to
            which the packet will be sent. This IP address represents the target host or device that the packet
            is intended for.
        hostIP
            The `hostIP` parameter in the `__init__` method is used to specify the host IP address. If a value
            is not provided for `hostIP` when creating an instance of the class, it will default to the local IP
            address obtained using `IPUtils().get_local_IP()`
        ttlCount, optional
            The `ttlCount` parameter in the `__init__` method is used to specify the Time-To-Live (TTL) value
            for the IP packets being sent. TTL is a value in the packet that limits the lifespan or lifetime of
            the packet in networking.
        timeout
            The `timeout` parameter in the `__init__` method is used to specify the time in seconds to wait for
            a response before considering a request as timed out. In this case, the default value for `timeout`
            is set to 0.3 seconds.
        
        '''
        instance._HOSTIP = hostIP # Default Gateaway, ну тупа роутер мне лень это объяснять
        instance._IP= IP(src= IPUtils().get_external_IP(),dst=dstIP, ttl=(1,ttlCount)) # Слой Ethernet, дист. неизвестна, тип пакета ARP 
        instance._ANSWERED_PORTS = [] # Массив "Живых" Хостов(Добавлен сразу DefaultGateaway потому что с него отправляются ARP запросы)
        instance._THREADS = [] # Массив Потоков
        instance._TIMEOUT = float(timeout)
        conf.verb = 0 # Вырубает нахуй все принты ебучего Scapy

    def scanUtil(instance, startNum, endNum):
        '''This Python function scans a range of ports for a given IP address using TCP requests and prints the
        open ports.
        
        Parameters
        ----------
        instance
            Instance is an object that contains information about the scanning process, such as IP address,
            timeout value, and answered ports list.
        startNum
            The `startNum` parameter in the `scanUtil` function represents the starting number of the range of
            ports to scan.
        endNum
            The `endNum` parameter in the `scanUtil` function represents the ending number of the range that is
            being scanned. The function iterates through the range of numbers starting from `startNum` up to and
            including `endNum`. This parameter helps define the range of ports that will be scanned.
        
        '''
        for x in range(startNum,endNum+1): # Идёт цикл с startNum до endNum, сделано так потому что данная функция делиться для много Threads для ускорения сканирования
            TCPRequst = instance._IP/TCP(dport=x,flags="S") # Обычный TCP пакет с flag-SYN
            ans, _ = sr(TCPRequst, timeout=instance._TIMEOUT) # Отсылается пакет, с timeout в 100 милисекунд(0.1 Секунды)
            if ans: # Если ответ получен

                #_____________________________ЧТЕНИЯ ОТВЕТА_____________________________
                capture = io.StringIO()
                save_stdout = sys.stdout
                sys.stdout = capture
                print(f"{ans.summary(lambda s, r: r.sprintf('{TCP:%TCP.flags%}'))}")  # noqa
                sys.stdout = save_stdout
                #_______________________________________________________________________
                PACKET_ITERATOR=0 # Итератор while-цикла
                while(PACKET_ITERATOR<3): # Из-за маленького timeout, пакет может дойти но не успеть отослать ответ, из-за этого отсылается 3 раза
                    if("SA" in capture.getvalue()):
                        print(f"[+]", end=""); print(x); # Принтует port который был обнаружен как "открытый"
                        instance._ANSWERED_PORTS.append(x) # Добавь в список живых хостов, дист. айпишник из оригинального пакета
                        break
                    PACKET_ITERATOR+=1


    def scan(instance, threadCount, startPort=0, endPort=1500, printOut=True):
        '''The `scan` function in Python scans a range of ports using multiple threads and prints out the open
        ports if specified.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `scan` function is an instance of a class that contains a method
            called `scanUtil`. This method is used as the target function for each thread that is created in the
            `scan` function.
        threadCount
            The `threadCount` parameter in the `scan` function specifies the number of threads that will be
            used to scan for open ports. It determines how many parallel threads will be created to scan the
            specified range of ports concurrently. Max threadCount is 15
        startPort, optional
            The `startPort` parameter in the `scan` function represents the starting port number from which the
            scanning will begin. By default, it is set to 0, but you can specify a different starting port if
            needed.
        endPort, optional
            The `endPort` parameter in the `scan` function represents the ending port number for the port
            scanning operation. This parameter specifies the last port number to be scanned in the range of
            ports. By default, it is set to 1500, but you can specify a different ending port number.
        printOut, optional
            The `printOut` parameter in the `scan` function is a boolean flag that determines whether the
            function should print the results of the port scanning operation or not.
        
        Returns
        -------
            The `scan` function returns the list of open ports stored in `instance._ANSWERED_PORTS`.
        
        '''
        if threadCount>15: 
            threadCount=15 # Не вижу смысла в больше потоках чем 15, один хуй там дело в милисекундах, ты ещё еблан на 1000 потоков его запусти

        total_numbers = endPort - startPort
        separation_size = total_numbers // threadCount
        remainder = total_numbers % threadCount


        separation = [] # Массив который будет содержать диапазоны IP-адресов для каждого потока ввиде List

        for i in range(threadCount):
            start = startPort + i * separation_size
            end = start + separation_size
            if i == threadCount - 1:
                end += remainder
            separation.append([start, end])  # Добавляем диапазон [start, end] в список разделов
        # Да мне лень было от комментировать 
        print(separation)
        for i in range(threadCount): # А тут уже создания самих потоков
            thread = threading.Thread(target=instance.scanUtil, args=(separation[i][0],separation[i][1])) # Сам поток, в который передаётся функция scanUtil, и диапозон IP текущего потока
            thread.start() # Запускаем поток
            instance._THREADS.append(thread) # И добавляем его в список потоков 
        
        for thread in instance._THREADS:
            thread.join()
    
        if(printOut):
            print("______________\n  OPEN-PORTS   \n______________")
            print(instance._ANSWERED_PORTS)

        return instance._ANSWERED_PORTS