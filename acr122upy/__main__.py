import argparse
import sys
from   time import sleep

from .device.acr122u import ACR122u
from .cards.mifare   import CardMifareClassic
from .cards.factory  import CardFactory

"""
    Definition of the main function body
"""
def main():
    # Argument parsing
    parser = argparse.ArgumentParser('acr122u')
    parser.add_argument('--getuid', action='store_true')
    arguments = parser.parse_args()

    # Added reader
    reader = ACR122u()
    CardFactory.create((0x00, 0x01))
    sleep(60)
    #print('firmware =', reader.firmware)
    #print('firmware =', reader.firmware)
    #print('uid      =', reader.get_uid())
    #print('ats      =', reader.get_ats())
    #print('\n\n\n')


    # Search for keys
    for block in range(64):
        for ktype in range(2):
            for key in CardMifareClassic.default_keys():
                if reader.auth(key, block=block, key_type=ktype)[-1] == 'Success':
                    print(f'Found key!!!! = (block={block},key_type={ktype})={key}')
                    break

        if block == 0:
            print(reader.block_read(block))

    return



    print('auth ='     , authorization)
    print('\n\n\n')

    if authorization[-1] == 'Success':
        for i in range(16):
            print(f'block[{i}] =', reader.block_read(i))

    #if arguments.getuid:
    #    reader.info()


"""
    Python binding for main script
"""
if __name__ == "__main__":
    sys.exit(main())
