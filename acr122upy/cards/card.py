from abc import ABC, abstractmethod

class ICard(ABC):
    @abstractmethod
    def is_unlocked(self):
        """
            Verifies if the card is unlocked (if we have authorization to read and write)
        """


    @abstractmethod
    def unlock(self, /, reader=None, path=None):
        """
            Gets authorization to read and write to card
        """


    @abstractmethod
    def block_read(self, block:int):
        """
            Reads binary data from block
        """


    @abstractmethod
    def block_write(self, block:int, data:list[int]):
        """
            Writes binary data from block
        """


    @abstractmethod
    def load_from_file(self, path:str):
        """
            Part of the deserialize API: read authentication and data from file
        """


    @abstractmethod
    def save_to_file(self, path:str):
        """
            Part of the deserialize API: save authentication and data to file
        """
