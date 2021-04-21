"""
    TODO: Factory Docstring
"""
# ##############################################################################
# Project imports
# ##############################################################################
from .mifare import CardMifareClassic


class CardFactory:
    """
        Creates card instances from 2 bytes of data comming from card readers
    """
    __parser:dict = \
    {
        # key          card name
        (0x00, 0x01): 'MIFARE Classic 1K',
        (0x00, 0x02): 'MIFARE Classic 4K',
        (0x00, 0x03): 'MIFARE Ultralight',
        (0x00, 0x26): 'MIFARE Mini'      ,
        (0xF0, 0x04): 'Topaz and Jewel'  ,
        (0xF0, 0x11): 'FeliCa 212K'      ,
        (0xF0, 0x11): 'FeliCa 424K'
    }

    @staticmethod
    def create(index:tuple, /, reader=None, path=None):
        assert len(index) == 2                              , 'tuple must have two elements'
        assert all(map(lambda x: isinstance(x, int), index)), 'all tuple element must be integer '

        # Get card label from tuple->card type parser
        card_label = CardFactory.__parser.get(index, 'unknown')

        if 'MIFARE' in card_label:
            return CardMifareClassic(card_label, reader=reader, path=path)

        raise Exception(f'Card type {card_label} is not supported')
