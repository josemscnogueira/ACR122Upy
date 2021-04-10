from smartcard.System import readers


class ACR122u:
    """
        Class that wraps the ACR122U device and associated functionality
    """
    __id:str                 = None
    __connection:str         = None

    def __init__(self):
        """
            Initializes device reference to the first device listed as ACR122U
            If no device is found, None is assigned to id
        """
        self.__id = next(filter(lambda x: 'ACR122U' in x.name, readers()), None)


    def __enter__(self):
        """
            Context manager "on enter"
        """
        self.open()
        return self


    def __exit__(self, etype, evalue, etrace):
        """
            Context manager "on exit"
        """
        self.close()


    def open(self):
        """
            Opens connection to device
        """
        assert self.__id, 'No devices are connected'
        self.__connection = self.__id.createConnection()
        self.__connection.connect()


    def close(self):
        """
            Closes connection
        """
        self.__connection = None

    def info(self):
        assert self.__connection, 'No connection is stablish. Please open the device first'
        print(self.__connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00]))
