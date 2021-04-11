# ##############################################################################
# System imports
# ##############################################################################
from collections.abc import Iterable
from collections     import namedtuple
from time            import process_time
import weakref


# ##############################################################################
# Imports from pyscard
# ##############################################################################
from smartcard.System           import readers
from smartcard.ReaderMonitoring import ReaderObserver, ReaderMonitor
from smartcard.CardMonitoring   import CardMonitor   , CardObserver
from smartcard.util             import toHexString



class ACR122u:
    """
        Class that wraps the ACR122U device and associated functionality
    """
    __monitor      = { 'reader' : ReaderMonitor(),
                       'card'   : CardMonitor()  }
    __filter:str   = None
    __reader       = None
    __card         = None

    def __init__(self, device='ACR122U'):
        """
            Initializes device reference to the first device listed as ACR122U
            If no device is found, None is assigned to id
        """
        self.__filter  = device
        self.__monitor['reader'].addObserver(ACR122u.__ReaderObserver(self))
        self.__monitor['card'  ].addObserver(ACR122u.__CardObserver(  self))

    def update(self, /, rnew:Iterable = tuple(), rold:Iterable = tuple()):
        """
            Adds   readers from rnew
            Remove readers from rold
                - As long as they match the __filter attribute
        """
        for reader in rnew:
            if not self.__filter or self.__filter in reader.name:
                self.__reader = reader
                print(f'Added reader {self.__reader}')
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
        if self.__reader:
            # Add cards from the some reader
            list_cards = list(filter(lambda x: self.__reader.name == x.reader, cnew))
            assert len(list_cards) <= 1

            for card in list_cards:
                self.__card = card
                print(f'Adding   card {card}')

            # Remove cards if the card is inserted
            list_cards = list(filter(lambda x: x == self.__card, cold))
            assert len(list_cards) <= 1

            if len(list_cards) == 1:
                self.__card = None
                print(f'Removing card {list_cards[0]}')


    @property
    def reader(self):
        return self.__reader

    def execute(self, command, /, timeout = 20):
        t_start = process_time()

        while process_time() < timeout:
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

    def info(self):
        cmd_getdata = namedtuple('get_data', ['cmdtype', 'ins', 'p1', 'p2', 'le'] )

        print("get uid = ", ACR122u.parse_response(self.execute(list(cmd_getdata(0xFF, 0xCA, 0x00, 0x00, 0x00)))))
        print("get ats = ", ACR122u.parse_response(self.execute(list(cmd_getdata(0xFF, 0xCA, 0x01, 0x00, 0x00)))))

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
