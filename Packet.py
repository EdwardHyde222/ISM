import uuid
import random
from random import randrange
from textwrap import wrap

from PacketExceptions import PacketExceptions


def randomizer(string_length: int = 10) -> str:
    """
    Creating some randomized string
    :param string_length: Amount of random symbols
    :return: Returns a random string of length string_length
    """
    # random = str(uuid.uuid4())  # Convert UUID format to a Python string.
    # random = random.upper()  # Make all characters uppercase.
    # random = random.replace("-", "")  # Remove the UUID '-'.
    # return random[0:string_length]  # Return the random string.
    return str(uuid.uuid4()).upper().replace("-", "")[0:string_length]


class Packet(PacketExceptions):
    def __init__(self, data: str = None, parsing_method: int = 32) -> str:
        """
        A class designed to encrypt information using specifically determined combinations and logic.
        :param data: Information that will be encrypted
        :param parsing_method: How many symbols are minimized to use (minimum = 32)
        """
        super(Packet, self).__init__()
        self.__combinations: dict = {
            'a': '1AL', 'h': '9HL', 'o': 'GOL', 'v': 'NVL',
            'b': '2BL', 'i': 'AIL', 'p': 'HPL', 'w': 'OWL',
            'c': '3CL', 'j': 'BJL', 'q': 'IQL', 'x': 'PXL',
            'd': '4DL', 'k': 'CKL', 'r': 'JRL', 'y': 'QYL',
            'e': '5EL', 'l': 'DLL', 's': 'KSL', 'z': 'RZL',
            'f': '6FL', 'm': 'EML', 't': 'LTL',
            'g': '7GL', 'n': 'FNL', 'u': 'MUL',

            'A': '1AU', 'H': '9HU', 'O': 'GOU', 'V': 'NVU',
            'B': '2BU', 'I': 'AIU', 'P': 'HPU', 'W': 'OWU',
            'C': '3CU', 'J': 'BJU', 'Q': 'IQU', 'X': 'PXU',
            'D': '4DU', 'K': 'CKU', 'R': 'JRU', 'Y': 'QYU',
            'E': '5EU', 'L': 'DLU', 'S': 'KSU', 'Z': 'RZU',
            'F': '6FU', 'M': 'EMU', 'T': 'LTU',
            'G': '7GU', 'N': 'FNU', 'U': 'MUU',

            ',': '1SA', '.': '2SB',
            '/': '3SC', '\\': '4SD',
            '<': '5SE', '>': '6SF',
            '[': '7SG', ']': '8SH',
            '!': '9SI', '?': 'ASJ',
            '(': 'BSK', ')': 'CSL',
            '$': 'DSM', '#': 'ESN',
            '~': 'FSO', "'": 'GSP',
            '`': 'HSQ', '|': 'ISR',
            '^': 'JSS', '&': 'KST',
            ';': 'LSU', ':': 'MSV',
            '+': 'NSW', '-': 'OSX',
            '=': 'PSY', '_': 'QSZ',
            ' ': 'RS1',
        }

        if parsing_method < 32:
            self.analyze('ValueError')
            parsing_method = 32

        self.__static_length: int = parsing_method
        self.__combo_length: int = 3

        if data is not None:
            self.__data = data
            self.encrypted_data = ''
            self.__allocate()
        else:
            self.analyze('ValueError')
            raise ValueError('Data value cannot be equal None!')

    def __del__(self):
        self.print()

    def __data_swapper(self, first_data: str, second_data: str) -> str:
        """
        Divides the lines into separate combinations of letters in the amount of 3 pieces and mixes them.
        :param first_data: First string - encrypted message by combo
        :param second_data: Second string - randomized string
        :return: Mixed encrypted message
        """

        def randomize_data_stock(amount: int):
            """
            Fills an array with random digits in a varied order
            :param amount: Amount of digits that will be in array
            :return: Mixed digits that complicated to an array
            """
            randomized: list = []
            for j in range(amount):
                randomized.append(randrange(0, j + randrange(1, j + 2)))
            return randomized
            # return np.random.randint(0, amount, size=amount)

        stocked_msg = wrap(first_data, self.__combo_length)
        stocked_str = wrap(second_data, self.__combo_length)
        randomized_stock = randomize_data_stock(len(stocked_str))

        for item in stocked_str:
            if len(item) != self.__combo_length:
                stocked_str.remove(item)
        for i in range(len(stocked_str)):
            # stocked_msg.insert(randomized_stock[i], stocked_str[i])
            # New shuffle string method will be more safe in encrypting
            stocked_msg.insert(randomized_stock[i], ''.join(random.sample(stocked_str[i], len(stocked_str[i]))))

        def validate_data(data: str):
            """
            Checks the cipher for the correct number of characters
            :param data: Mixed encrypted message
            :return: Checked mixed encrypted message
            """
            while len(data) < self.__static_length:
                data += randomizer(1)

            if abs(len(data) - self.__static_length) > 5:
                while len(data) % self.__static_length != 0:
                    data += randomizer(1)
            return data

        return validate_data(' '.join(stocked_msg).replace(' ', ''))

    def __allocate(self):
        packet_value = ''

        sliced_data = ''
        if len(self.__data) > int(self.__static_length / 2):
            new_data = ''
            for i in range(int(self.__static_length / 2)):
                new_data += self.__data[i]

            for i in range(int(self.__static_length / 2), len(self.__data)):
                sliced_data += self.__data[i]
            self.__data = new_data

        for letter in self.__data:
            # if letter in self.__static_combs or letter == ' ':
            #     packet_value += letter
            # else:
            for combo in self.__combinations:
                if letter == combo:
                    packet_value += self.__combinations.get(letter)
                    break

        allocated_mem: int = int(self.__static_length) - len(packet_value)
        # print(packet_value)
        # self.encrypted_data += complited + self.randomizer(string_length=allocated_mem)
        # increased basic encrypt logic
        self.encrypted_data += self.__data_swapper(packet_value, randomizer(string_length=allocated_mem))

        if sliced_data != '':
            # self.encrypted_data += '%'
            self.__data = sliced_data
            self.__allocate()
