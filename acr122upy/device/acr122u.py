# ##############################################################################
# System imports
# ##############################################################################
from collections.abc import Iterable
from collections     import namedtuple
from time            import time, sleep
import weakref


# ##############################################################################
# Imports from pyscard
# ##############################################################################
from smartcard.System           import readers
from smartcard.ReaderMonitoring import ReaderObserver, ReaderMonitor
from smartcard.CardMonitoring   import CardMonitor   , CardObserver
from smartcard.util             import toHexString
from smartcard.ATR              import ATR



_PARSER_CARD:dict = \
{
    (0x00, 0x01): "MIFARE Classic 1K",
    (0x00, 0x02): "MIFARE Classic 4K",
    (0x00, 0x03): "MIFARE Ultralight",
    (0x00, 0x26): "MIFARE Mini",
    (0xF0, 0x04): "Topaz and Jewel",
    (0xF0, 0x11): "FeliCa 212K",
    (0xF0, 0x11): "FeliCa 424K"
}


class ACR122u:
    """
        Class that wraps the ACR122U device and associated functionality
    """
    __monitor:dict = None
    __filter:str   = None
    __reader       = None
    __card         = None
    __firmware:str = None

    def __init__(self, device='ACR122U', period=1):
        """
            Initializes device reference to the first device listed as ACR122U
            If no device is found, None is assigned to id
        """
        self.__filter  = device
        self.__monitor = { 'reader' : ReaderMonitor(period=period),
                           'card'   : CardMonitor()               ,
                           'period' : period                      ,
                           'last'   : time()                      }
        self.__monitor['reader'].addObserver(ACR122u.__ReaderObserver(self))
        self.__monitor['card'  ].addObserver(ACR122u.__CardObserver(  self))


    def update(self, /, rnew:Iterable = tuple(), rold:Iterable = tuple()):
        """
            Adds   readers from rnew
            Remove readers from rold
                - As long as they match the __filter attribute
        """
        self._refreshed()

        for reader in rnew:
            if not self.__filter or self.__filter in reader.name:
                self.__reader = reader
                print(f'Added   reader {self.__reader}')
        for reader in rold:
            if not self.__filter or self.__filter in reader.name:
                print(f'Removed reader {self.__reader}')
                self.__reader = None

    def update_card(self, cnew:Iterable = tuple(), cold:Iterable = tuple()):
        """
            ACR122u only reads a "card" -> tag at a time.
            This is managed internall by the device. In this case, we are
            guaranteed that only one device is added or removed
        """
        self._refreshed()

        if self.__reader:
            # Add cards from the some reader
            list_cards = list(filter(lambda x: self.__reader.name == x.reader, cnew))
            assert len(list_cards) <= 1

            for card in list_cards:
                card.type   = _PARSER_CARD.get(tuple(card.atr[-7:-5]), 'UNKNOWN')
                self.__card = card
                print(f'Added   card{card.__dict__}')

            # Remove cards if the card is inserted
            list_cards = list(filter(lambda x: x == self.__card, cold))
            assert len(list_cards) <= 1

            if len(list_cards) == 1:
                self.__card = None
                print(f'Removed card {list_cards[0]}')


    def _refreshed(self):
        """
            This tells the instance that the monitor was updated,
            no timeouts can occur between the update and update+period
        """
        self.__monitor['last'] = time()


    def _stall(self):
        """
            the instance sleeps until last+period
        """
        t = self.__monitor['last'] + self.__monitor['period'] - time()
        if t > 0:
            sleep(t)


    @property
    def reader(self):
        return self.__reader

    def execute(self, command, /, timeout = 20):
        self._stall()

        t_start = time()

        while (time() - t_start) < timeout:
            if self.__card:
                self.__card.connection = self.__card.createConnection()
                self.__card.connection.connect()

                # Transmit command
                try:
                    return self.__card.connection.transmit(command)
                finally:
                    del self.__card.connection
        # If the timeout was reached, let's raise exceptions:
        else:
            if not self.__reader:
                raise Exception('No reader is connected with USB')
            if not self.__card:
                raise Exception('No tag is connected')
            else:
                raise Exception('Fatal error')


    @staticmethod
    def parse_response(response):
        cmd_response    = namedtuple('cmd_response', ['data', 'sw1', 'sw2', 'message'] )
        data, sw1, sw2  = response
        if (sw1, sw2) == (0x90, 0x00):
            message = 'Success'
        elif (sw1, sw2) == (0x63, 0x00):
            message = 'Failed'
        elif (sw1, sw2) == (0x6A, 0x81):
            message = 'Not Supported'
        else:
            message = 'Unknown'

        return cmd_response(toHexString(data), toHexString([sw1]), toHexString([sw2]), message)


    # ##########################################################################
    # Commands
    # ##########################################################################
    def get_uid(self):
        return ACR122u.parse_response(self.execute([0xFF, 0xCA, 0x00, 0x00, 0x00]))

    def get_ats(self):
        return ACR122u.parse_response(self.execute([0xFF, 0xCA, 0x01, 0x00, 0x00]))


    @property
    def firmware(self):
        """
            Gets firmware
            If firmware was not available, it will be retrived.
            Due to restrictions of pyscard or the device itself, we need to have a
            tag connected, in order to obtain the device firmware
        """
        if self.__firmware is None:
            result = ACR122u.parse_response(self.execute([0xFF, 0x00, 0x48, 0x00, 0x00]))
            self.__firmware = ''.join(chr(int(x, base=16)) for x in (result.data.split(' ') + [result.sw1, result.sw2]))

        return self.__firmware


    # ##########################################################################
    # Helper classes                                                           #
    # ##########################################################################
    class __ReaderObserver(ReaderObserver):
        """
            Observers readers and notifies
        """
        def __init__(self, monitor):
            """
                We need to create a weak reference to the monitor
            """
            self.__monitor = weakref.ref(monitor)


        def update(self, observable, handlers):
            """
                Overload to smartcard.ReaderMonitoring.ReaderObserver
                update method
            """
            self.__monitor().update(rnew=handlers[0], rold=handlers[1])


    class __CardObserver(CardObserver):
        """
            Observeres readers and notifies
        """
        def __init__(self, monitor):
            """
                We need to create a weak reference to the monitor
            """
            self.__monitor = weakref.ref(monitor)


        def update(self, observable, actions):
            """
                TODO:
            """
            self.__monitor().update_card(cnew=actions[0], cold=actions[1])
