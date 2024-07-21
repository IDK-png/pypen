from scapy.all import *
import threading
import sys
import io
from pypenlib.scanner.iputils import IPUtils
class UDPSCAN:
    def __init__(instance, dstIP, timeout=2):
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
        instance._APPLICATION_LAYER = DNS(qd=DNSQR()) # DNS Запрос
        instance._TRANSPORT_LAYER =  UDP()     # UDP Протокол
        instance._INTERNET_LAYER= IP(dst=dstIP)       # IP  Маршрутизатор

        instance._OPEN_PORTS = [] # Массив Открытых и Фильтрованных портов
        instance._OF_PORTS = []   # Массив Открытых|Фильтрованных портов

        instance._THREADS = []              # Массив Потоков
        instance._TIMEOUT = float(timeout)  # Таймаут сокета
        conf.verb = 0                       # Вырубает нахуй все принты ебучего Scapy

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
            UDPRequest = instance._INTERNET_LAYER/instance._TRANSPORT_LAYER/instance._APPLICATION_LAYER # Обычный UDP пакет с DNS запросов 
            UDPRequest[UDP].dport = x

            ans,_ = sr(UDPRequest, timeout=instance._TIMEOUT, verbose=False) 
            ans = [v for v in ans]; _ = [v for v in _]

            if(len(ans)): # Если был получен ответ(UDP/ICMP)
                for send,receive in ans:
                    if((receive.haslayer(ICMP) and receive[ICMP].type==3 and receive[ICMP].code == 3)==False): # Если ответ не является ICMP пакетом с кодом ошибки Destination Unreachable тогда порт или open или flitered
                            addStr = f"{x} | "
                            if(receive.haslayer(UDP)): # Если в ответе есть UDP пакет, нету смысла проверять так как при ошибки не посылаются UDP пакеты
                                receive[UDP].show()
                                addStr+="open" # Порт - Open
                            elif(receive.haslayer(ICMP)): # Если в ответе ICMP
                                addStr+="filtered" # Порт - Filtered
                            instance._OPEN_PORTS.append(addStr)
            if(len(_) and instance._OPENSCAN): # Если был проигнорирован
                instance._OF_PORTS.append(f"{x} | open-filtered") # Значит порт open-filtered

    def scan(instance, threadCount, startPort=0, endPort=1500, scanOpenFiltered=True, printOut=True):
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
            The `scan` function returns the list of open ports stored in `instance._OPEN_PORTS`.
        
        '''
        instance._OPENSCAN = scanOpenFiltered
        if threadCount>15: 
            threadCount=15 # Не вижу смысла в больше потоках чем 15, один хуй там дело в милисекундах, ты ещё еблан на 1000 потоков его запусти

        total_numbers = endPort - startPort
        separation_size = total_numbers // threadCount
        remainder = total_numbers % threadCount


        separation = [] # Массив который будет содержать диапазоны портов для каждого потока ввиде List

        for i in range(threadCount):
            start = startPort + i * separation_size
            end = start + separation_size
            if i == threadCount - 1:
                end += remainder
            separation.append([start, end])  # Добавляем диапазон [start, end] в список разделов
        # Да мне лень было от комментировать 
        for i in range(threadCount): # А тут уже создания самих потоков
            thread = threading.Thread(target=instance.scanUtil, args=(separation[i][0],separation[i][1])) # Сам поток, в который передаётся функция scanUtil, и диапозон IP текущего потока
            thread.start() # Запускаем поток
            instance._THREADS.append(thread) # И добавляем его в список потоков 
        
        for thread in instance._THREADS:
            thread.join()
    
        if(printOut):
            print("______________\n  OPEN-UDP-PORTS   \n______________")
            print(instance._OPEN_PORTS)

        return instance._OPEN_PORTS