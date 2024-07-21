from scapy.all import *
import threading
from pypenlib.scanner.iputils import IPUtils
class ARPSCAN:
    def __init__(instance, hostIP=IPUtils().get_local_IP(), timeout=0.1):
        '''This function initializes a network scanning tool using Scapy in Python, setting default values for
        local IP, Ethernet layer, answered hosts, threads, and disabling verbose output.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `__init__` method refers to the instance of the class that is being
            initialized. It is a reference to the object itself. When you create an object of a class and call
            its constructor (`__init__` method in Python), the `instance` parameter
        hostIP
            The `hostIP` parameter in the `__init__` method is used to specify the local IP address for the
            instance. By default, it is set to the result of `IP().get_local_network()` which presumably
            retrieves the local network IP address.
        '''
        instance._HOSTIP = hostIP # Default Gateaway, ну тупа роутер мне лень это объяснять
        instance._ETHER = Ether(dst="ff:ff:ff:ff:ff:ff",type="ARP") # Слой Ethernet, дист. неизвестна, тип пакета ARP 
        instance._ANSWERED = [instance._HOSTIP] # Массив "Живых" Хостов(Добавлен сразу DefaultGateaway потому что с него отправляются ARP запросы)
        instance._THREADS = [] # Массив Потоков
        instance._TIMEOUT = float(timeout)
        conf.verb = 0 # Вырубает нахуй все принты ебучего Scapy

    def scanUtil(instance, startNum, endNum):
        '''The function `scanUtil` performs ARP scanning within a specified range of IP addresses.
        Parameters
        ----------
        instance
            Instance is an object that contains information about the network configuration and settings. It
            likely includes attributes such as _HOSTIP (the local IP address), _ETHER (Ethernet frame
            information), and _ANSWERED (a list to store ARP responses).
        startNum
            The `startNum` parameter in the `scanUtil` function represents the starting number for iterating
            through a range of IP addresses. This parameter is used to specify the beginning of the range of IP
            addresses that will be scanned during the network scanning process.
        endNum
            The `endNum` parameter in the `scanUtil` function represents the ending number for the IP address
            range that will be scanned. The function will iterate from `startNum` to `endNum` to generate IP
            addresses within that range for scanning.       
        '''
        CurrentIP = instance._HOSTIP.split(".") # Разедляет айпишник в массив из 4 цифр, для более удобного изменения последней цифры
        for x in range(startNum,endNum): # Идёт цикл с startNum до endNum, сделано так потому что данная функция делиться для много Threads для ускорения сканирования
            CurrentIP[3] = str(x) # Меняется последняя цифра айпишника так как сканируется локалка
            LocalARP = ARP(psrc=instance._HOSTIP,pdst=".".join(CurrentIP)) # Слой ARP, в источнике ставиться айпишник роутера, а в дист. ставиться CurrentIP

            PACKET_ITERATOR=0 # Итератор while-цикла
            while(PACKET_ITERATOR<3): # Из-за маленького timeout, пакет может дойти но не успеть отослать ответ, из-за этого отсылается 3 раза
                ans, _ = srp(instance._ETHER/LocalARP, timeout=instance._TIMEOUT) # Отсылается пакет, с timeout в 100 милисекунд(0.1 Секунды)
                if ans: # Если ответ получен
                    #_________________Для Дебага__________________
                    #    for sent, received in ans:
                    #    print(f"Отправлено: {sent.summary()}")
                    #    print(f"Получено: {received.summary()}")
                    #_____________________________________________
                    instance._ANSWERED.append(LocalARP[ARP].pdst) # Добавь в список живых хостов, дист. айпишник из оригинального пакета
                    break # если ответ получен выйди нахуй с цикла, нахуя тебе ещё пакеты отсылать если ты один хуй получил ответ ебланище тупое нахуй
                PACKET_ITERATOR+=1 # ну бля если ты не понимаешь нахуя это здесь то ты еблан полнейщий, нахуй с репозитория вышел


    def scan(instance, threadCount, printOut=True):
        '''The `scan` function divides a range of numbers into separation based on the specified thread count,
        creates threads to execute a `scanUtil` method on each chunk, and prints or returns the results.
        
        Parameters
        ----------
        instance
            The `instance` parameter in the `scan` function is an object that is used to call the `scanUtil`
            method.
        threadCount parameter in the `scan` function represents the number of threads that will be
            used to divide the scanning process. It determines how many parallel threads will be created to scan
            the target.

        printOut, optional
            The `printOut` parameter in the `scan` function is a boolean parameter that determines whether the
            function should print the results to the console or not.

        Returns
        -------
            If the `printOut` parameter is set to `False`, the function will return `instance._ANSWERED`, which contains information about live hosts.
        
        '''
        if threadCount>15: 
            threadCount=15 # Не вижу смысла в больше потоках чем 15, один хуй там дело в милисекундах, ты ещё еблан на 1000 потоков его запусти

        limitIP = 256 # Ну мля, 8 битов просто в цифре 
        separation_size = limitIP // threadCount # Делит 8 битов на число потоков получая целое число в итоге
        remainder = limitIP % threadCount # Остаток деление на число потоков 8 битов, добавиться в endNum последнего потока

        separation = [] # Массив который будет содержать диапазоны IP-адресов для каждого потока ввиде List

        for i in range(threadCount):  # Проходим по каждому потоку от 0 до threadCount-1
            start = i * separation_size  # Вычисляем начальный IP-адрес для текущего потока
            end = start + separation_size  # Вычисляем конечный IP-адрес для текущего потока
            if i == threadCount - 1:  # Если это последний поток
                end += remainder  # Добавляем остаток к конечному IP-адресу, чтобы захватить оставшиеся IP-адреса
            separation.append([start, end])  # Добавляем диапазон [start, end] в список разделов
        # Да мне лень было от комментировать 

        for i in range(threadCount): # А тут уже создания самих потоков
            thread = threading.Thread(target=instance.scanUtil, args=(separation[i][0],separation[i][1])) # Сам поток, в который передаётся функция scanUtil, и диапозон IP текущего потока
            thread.start() # Запускаем поток
            instance._THREADS.append(thread) # И добавляем его в список потоков 
        
        for thread in instance._THREADS:
            thread.join()
    
        if(printOut):
            print("______________\n  LIVE-HOSTS  \n______________")
            print(instance._ANSWERED)

        return instance._ANSWERED