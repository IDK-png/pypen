from scapy.all import *
import threading
import sys
import io
import colorama
from colorama import Fore, Style
from pypenlib.scanner.iputils import IPUtils
class TCPSCAN:
    def __init__(instance, dstIP, hostIP=IPUtils().get_local_IP(), ttlCount=15, timeout=0.3):
        instance._HOSTIP = hostIP # Default Gateaway, ну тупа роутер мне лень это объяснять
        instance._IP= IP(src= IPUtils().get_external_IP(),dst=dstIP, ttl=(1,ttlCount)) # Слой Ethernet, дист. неизвестна, тип пакета ARP 
        instance._ANSWERED_PORTS = [] # Массив "Живых" Хостов(Добавлен сразу DefaultGateaway потому что с него отправляются ARP запросы)
        instance._THREADS = [] # Массив Потоков
        instance._TIMEOUT = float(timeout)
        conf.verb = 0 # Вырубает нахуй все принты ебучего Scapy

    def scanUtil(instance, startNum, endNum):
        for x in range(startNum,endNum+1): # Идёт цикл с startNum до endNum, сделано так потому что данная функция делиться для много Threads для ускорения сканирования
            TCPRequst = instance._IP/TCP(dport=x,flags="S")
            ans, _ = sr(TCPRequst, timeout=instance._TIMEOUT) # Отсылается пакет, с timeout в 100 милисекунд(0.1 Секунды)
            if ans: # Если ответ получен

                #___________________________________________________________________
                capture = io.StringIO()
                save_stdout = sys.stdout
                sys.stdout = capture
                print(f"{ans.summary( lambda s,r: r.sprintf("{TCP:%TCP.flags%}"))}")
                sys.stdout = save_stdout
                #___________________________________________________________________
                PACKET_ITERATOR=0 # Итератор while-цикла
                while(PACKET_ITERATOR<3): # Из-за маленького timeout, пакет может дойти но не успеть отослать ответ, из-за этого отсылается 3 раза
                    if("SA" in capture.getvalue()):
                        print(f"[+]", end="")
                        print(x)
                        instance._ANSWERED_PORTS.append(x) # Добавь в список живых хостов, дист. айпишник из оригинального пакета
                        break
                    PACKET_ITERATOR+=1


    def scan(instance, threadCount, startPort=0, endPort=1500, printOut=True):
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

        else:
            return instance._ANSWERED_PORTS