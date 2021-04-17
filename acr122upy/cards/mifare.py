"""
    SOURCES: [1] A Practical Attack on the MIFARE Classic by Gerhard de Koning Gans, Jaap-Henk Hoepman, and Flavio D. Garcia
             [2] ACR122U Application Programming Interface V2.04 Document

    --------------------------------------------------------------------------------------------------------------------

    MIFARE is a product family of smart cards compliant with ISO 14443 up to part 3.

    Note: but they are not complaint with ISO 14443 part 4 (high level protocol)

    This module focused on the MIFARE Classic smartcards
        - it's a memory card
        - has additional (but limited) functionality (computational abilty)
                                                     ( != RFID)

    * Memory is devided into blocks of 16 bytes
    * Blocks are grouped into sectors

    MIFARE Classic 1K has 16 sectors with  4 blocks each
           [total] 64 (0x40) blocks or 1024 (0x400) bytes

    MIFARE Classic 4K has 32 sectors with  4 blocks each
                     plus  8 sectors with 16 blocks each

    * The last block of each sector is called the TRAILER sector
    * The first block of the first sector is READ-ONLY and contains the following data:

      | [0:4[ | 4   | [5:16[            |
      | ----- | --- | ----------------- |
      | UID   | BCC | MANUFACTURER INFO |

    * where the UID is the unique identified of the card
    *       the BCC is Bit Count Check - XOR operation of the first 4 bytes UID
    *       the remaining bytes are reserved for manufacturer information

    * For all sectors, the last block - SECTOR TRAILER - contains two keys - KEY_A and KEY_B
    * These keys are used for authentication, meaning that data can only be read or writtin, within this sector, if
      the authentication keys are used for authentication -> they will unlock that sector.
    * The SECTOR TRAILER contains the following information:

      | [0:6[ | [6:10[ | [10:16[ |
      | ----- | ------ | ------- |
      | KEY_A | AC_CD  | KEY_B   |

      where KEY_A and KEY_B are te authentication keys and AC_CD are referenced as the Access Conditions. These Accesss
      Conditions define which operations are permited in that specific sector. The last byte (4th) is actually
      irrelevant and, therefore, can be used for storage

    * Searching for these keys with pure bruteforce is completly futile with Serial communications (note: 2021-04-17)

    * Even thought the sector access is specified by the Access Conditions, the SECTOR TRAILER (last block of each
      sector) has special conditons. Namely, KEY_A is never readable and KEY_B may or may not be readable

    * All other blocks can be used as:
        - Data  Blocks: used to store arbitrary data
        - Value Blocks: used to store a 4 byte value, following a specfic memory schema:

        | [0:4[ | [4:8[   | [8:12[ | 12 | 13 | 14 | 15 |
        | ----- | ------- | ------ | -- | -- | -- | -- |
        | VALUE |  ~VALUE | VALUE  |  A | ~A |  A | ~A |

        where VALUE is the 4-byte value to be stored (bytes are stored from the LSB (left) to MSB (right))
             ~VALUE is bitwise negation of VALUE (or bitwise XOR of VALUE with 1)
              A is the address byte (in the same way, ~A is the bitwise negation of A). A can be used as a pointer ???

    * MIFARE Classic cards support the following operations:
          - Read and Write of data block
          - Increment, decrement, restore and transfer value blocks
                >> increment and decrement value inside the block and loads it into the memory register
                >> restore only loads the value insde the block and loads it into the memory register
                >> transfer will store the value loaded into the memory register into the same value block or to another
                   specified by the command
"""

# ##############################################################################
# Project imports
# ##############################################################################
from .card import ICard

"""
    Default Authorization keys found in https://awesomeopensource.com/project/XaviTorello/mifare-classic-toolkit
"""
_DEFAULT_KEYS = ([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF], \
                 [0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0], \
                 [0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1], \
                 [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], \
                 [0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5], \
                 [0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD], \
                 [0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A], \
                 [0x00, 0x00, 0x00, 0x00, 0x00, 0x00], \
                 [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], \
                 [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7], \
                 [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], \
                 [0x71, 0x4C, 0x5C, 0x88, 0x6E, 0x97], \
                 [0x58, 0x7E, 0xE5, 0xF9, 0x35, 0x0F], \
                 [0xA0, 0x47, 0x8C, 0xC3, 0x90, 0x91], \
                 [0x53, 0x3C, 0xB6, 0xC7, 0x23, 0xF6], \
                 [0x8F, 0xD0, 0xA4, 0xF2, 0x56, 0xE9]  )




class CardMifareClassic(ICard):
    # ##########################################################################
    # Attributes
    # ##########################################################################
    __blocks:int = 0
    __keys:dict  = dict()
    __auth:int   = None

    __uid:tuple  = None
    __bcc:int    = None
    __man:tuple  = None

    def __init__(self, card_type, /, reader=None, path=None):
        """
            Initialization of a MIFARE Classic card
                - Depends on the type of card
                - Initial authentication depends if there's a reader available
                  or if there's a path where we can read pre-loaded keys
                  for a mathing UID
                - Depends if there's an actual reader available
        """
        if (card_type == 'MIFARE Classic 1K'):
            self.__blocks = 0x40  # 1KBytes
        elif (card_type == 'MIFARE Classic 4K'):
            self.__blocks = 0x100 # 4KBytes
        else:
            raise NotImplementedError

        # Create keys for the first time
        self.__keys = { b:None for b in range(self.__blocks) }

        # If reader is availailable, let's get all authentication keys
        if reader:
            self.read_info(reader)

        # Unlock card using reader and/or path
        self.unlock(reader=reader, path=path)


    # ##########################################################################
    # Implementations of Abstract class: ICard
    # ##########################################################################
    def is_unlocked(self):
        """
            Card is unlocked if the number of blocks is unitialized and we know the
            authentication keys for each block
        """
        return self.__blocks != 0 and all((v is not None for v in self.__keys.values()))


    @staticmethod
    def default_keys():
        yield from _DEFAULT_KEYS
