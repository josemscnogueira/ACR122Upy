import argparse
import sys
from   time import sleep

from .device.acr122u import ACR122u

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
    sleep(1)


    reader.info()

    if arguments.getuid:
        reader.info()


"""
    Python binding for main script
"""
if __name__ == "__main__":
    sys.exit(main())
