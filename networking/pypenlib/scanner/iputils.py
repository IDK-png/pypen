from scapy.all import *
class IPUtils:
    def __init__(instance) -> None:
        # Нахуй тут конструктор не всрался
        pass
    def get_local_IP(instance) -> str:
        '''The function `get_local_network` retrieves the first local network IP address from a list of routes.
        
        Parameters
        ----------
        instance
            It is a reference to the object itself. When you create an object of a class and call
            its constructor (`__init__` method in Python), the `instance` parameter
        
        Returns
        -------
            The function `get_local_network` returns the first network IP address from the list of network IP
            addresses that are within the specified IPv4 ranges (192.x.x.x, 172.x.x.x, 10.x.x.x) obtained from
            the `read_routes()` function.
        
        '''
        IPv4ranges = ["192","172","10"] # Единственные три диапозона IPv4 в локальных сетях, если у вас другой то идите нахуй, выживайте сами как-то, хитровыебанные блять.
        for x in read_routes(): # Смотрит все маршруты в сети
            currentNetwork = x[2] # Выбирает только IP из всего Tuple'а
            if(currentNetwork.split('.')[0] in IPv4ranges): # Если айпишник входит в диапозон то...
                return currentNetwork         # Добавляй в список

    def get_external_IP(instance) -> str:
        IPv4ranges = ["192","172","10"] # Единственные три диапозона IPv4 в локальных сетях, если у вас другой то идите нахуй, выживайте сами как-то, хитровыебанные блять.
        for x in read_routes(): # Смотрит все маршруты в сети
            currentNetwork = x[2] # Выбирает только IP из всего Tuple'а
            if(currentNetwork.split('.')[0] in IPv4ranges): # Если айпишник входит в диапозон то...
                return x[4]
        return "0.0.0.0"