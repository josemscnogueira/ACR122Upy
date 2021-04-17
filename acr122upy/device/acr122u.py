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
    # key            card name           number of blocks of 16 bytes (memory)
    (0x00, 0x01): ('MIFARE Classic 1K' , 0x040     ),
    (0x00, 0x02): ('MIFARE Classic 4K' , 0x100     ),
    (0x00, 0x03): ('MIFARE Ultralight' , 0xFFFFFFFF),
    (0x00, 0x26): ('MIFARE Mini'       , 0xFFFFFFFF),
    (0xF0, 0x04): ('Topaz and Jewel'   , 0xFFFFFFFF),
    (0xF0, 0x11): ('FeliCa 212K'       , 0xFFFFFFFF),
    (0xF0, 0x11): ('FeliCa 424K'       , 0xFFFFFFFF)
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
    # Commands: Infos
    # ##########################################################################
    def get_uid(self):
        return ACR122u.parse_response(self.execute([0xFF, 0xCA, 0x00, 0x00, 0x00]))

    def get_ats(self):
        return ACR122u.parse_response(self.execute([0xFF, 0xCA, 0x01, 0x00, 0x00]))


    # ##########################################################################
    # Commands: Authentication
    # ##########################################################################
    def __load_auth_key(self, key:list[int], /, key_number:int=0x00):
        """
            Loads authentication key into the reader volatile memory
            The key is a byte list (integeres) with length 6
            Possible key numbers are 0 or 1. There are two volatile memory addresses in this reader
        """
        assert isinstance(key, list)
        assert len(key) == 6
        assert all(map(lambda x: isinstance(x, int), key))
        assert key_number == 0 or key_number == 1

        return ACR122u.parse_response(self.execute([0xFF, 0x82, 0x00, key_number, 0x06] + key))


    def __commit_auth(self, block:int, key_type:int, /, key_number:int=0x00):
        """
            According the documentation:
                This command uses the keys stored in the reader to do
                authentication with the MIFARE 1K/4K card (PICC). Two types of
                authentication keys are used: TYPE_A and TYPE_B.

            Authenticates (card) with the key loaded into memory
                - Memory slot is given by the key_number
                - block is the memory sector we which to unlock in the card
                - key_type: TYPE_A = 0, TYPE_B = 1
        """
        assert 0 <= block  <  self._block_max(), f'block size provided ({block}) is bigger than allowed ({self._block_max()})'
        return ACR122u.parse_response(self.execute([0xFF, 0x86, 0x00 , 0x00           , 0x05] + \
                                                   [0x01, 0x00, block, 0x60 + key_type, key_number]))


    def auth(self, key:list[int], /, block:int, key_type:int):
        """
            Function joins loading the authentication key into volatile memory
            And commits this key in order to unblock a specific memory sector
                param key : list of integers with size 6
                block     : any block id of the target sector
                key_type  : 0 if TYPE_A, 1 if TYPE_B
        """
        result = self.__load_auth_key(key, key_number=key_type)
        if result[-1] == 'Success':
            result = self.__commit_auth(block, key_type, key_number=key_type)

        return result


    # ##########################################################################
    # Commands: Data
    # ##########################################################################
    def block_read(self, block:int, length:int = 16):
        """
            Reads binary data from tag/card
            The block index must be provided and it depends on the card type
            The length is the size to read in that block. Its value can be from
            0 to 16.
        """
        assert 0 <= block  <  self._block_max(), f'block size provided ({block}) is bigger than allowed ({self._block_max()})'
        assert 0 <= length <= 16               , f'maximum length to read from block is 16'

        return ACR122u.parse_response(self.execute([0xFF, 0xB0, 0x00, block, length]))


    # ##########################################################################
    # Commands: Reader only
    # ##########################################################################
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


    def _block_max(self):
        """
            Returns the block size depending on card type
        """
        return self.__card.type[1] if self.__card else 0xFFFFFFFF


    def _sector_max(self):
        """
            Returns the sector size depending on card type
        """
        return self._block_max() / 4


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
