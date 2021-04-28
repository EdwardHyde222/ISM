import uuid
from textwrap import wrap

import numpy as np


class PacketExceptions:
    def __init__(self):
        self.__version = '27.04.2021 / P-Exceptions v.1'
        self.__errors = {
            'IndexError': 0,
            'ValueError': 0,
            'Exception': 0,
            'BufferError': 0,
        }

    def analyze(self, error_type: str = None) -> None:
        for types in self.__errors:
            if error_type == types:
                self.__errors[types] += 1

    def print(self, error_type: str = None) -> None:
        if error_type is not None:
            for item in self.__errors:
                if error_type == item:
                    print("{} x{}".format(item, self.__errors[item]))
                    break
        else:
            for item in self.__errors:
                print("{} x{}".format(item, self.__errors[item]))


def randomizer(string_length=10):
    """
    Creating some randomized string
    :param string_length: Amount of random symbols
    :return: Returns a random string of length string_length
    """
    random = str(uuid.uuid4())  # Convert UUID format to a Python string.
    random = random.upper()  # Make all characters uppercase.
    random = random.replace("-", "")  # Remove the UUID '-'.
    return random[0:string_length]  # Return the random string.


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
        }
        self.__static_combs: list = [
            ',', '.',
            '/', '\\',
            '<', '>',
            '[', ']',
            '!', '?',
            '(', ')',
            '$', '#',
            '!', '~',
            '`', '|',
            '^', '&',
            ';', ':',
            '+', '-',
            '=', '_',
            "'",
        ]
        self.static_length: int = parsing_method
        self.combo_length: int = 3
        # Featured function
        # if self.static_length / 2 < len(data):
        #     raise ValueError('Value of encrypting method cannot be lower than string length!')

        if data is not None:
            self.data = data
            self.encrypted_data = ''
            self.allocate()

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
            return np.random.randint(0, amount, size=amount)

        stocked_msg = wrap(first_data, self.combo_length)
        stocked_str = wrap(second_data, self.combo_length)
        randomized_stock = randomize_data_stock(len(stocked_str))
        for item in stocked_str:
            if len(item) != self.combo_length:
                stocked_str.remove(item)
        for i in range(len(stocked_str)):
            stocked_msg.insert(randomized_stock[i], stocked_str[i])

        def validate_data(data: str):
            """
            Checks the cipher for the correct number of characters
            :param data: Mixed encrypted message
            :return: Checked mixed encrypted message
            """
            while len(data) < self.static_length:
                data += randomizer(1)

            if abs(len(data) - self.static_length) > 5:
                while len(data) % self.static_length != 0:
                    data += randomizer(1)
            return data

        return validate_data(' '.join(stocked_msg).replace(' ', ''))

    def allocate(self):
        complited = ''

        sliced_data = ''
        if len(self.data) > int(self.static_length / 2):
            new_data = ''
            for i in range(int(self.static_length / 2)):
                new_data += self.data[i]

            for i in range(int(self.static_length / 2), len(self.data)):
                sliced_data += self.data[i]
            self.data = new_data

        for letter in self.data:
            if letter in self.__static_combs or letter == ' ':
                complited += letter
            else:
                for combo in self.__combinations:
                    if letter == combo:
                        complited += self.__combinations.get(letter)
                        break

        allocated_mem: int = int(self.static_length) - len(complited)
        # self.encrypted_data += complited + self.randomizer(string_length=allocated_mem)
        # increased basic encrypt logic
        self.encrypted_data += self.__data_swapper(complited, randomizer(string_length=allocated_mem))

        if sliced_data != '':
            # self.encrypted_data += '%'
            self.data = sliced_data
            self.allocate()

    def deploy(self, data: str):
        recomplited = ''

        for index in range(len(data)):
            if data[index] in self.__static_combs or data[index] == ' ':
                recomplited += data[index]
            else:
                for combo in self.__combinations:
                    try:
                        complimented_letters = data[index] + data[index + 1] + data[index + 2]

                        if complimented_letters == self.__combinations.get(combo, ''):
                            res = dict((v, k) for k, v in self.__combinations.items())
                            recomplited += str(res.get(complimented_letters))
                            break

                    except Exception:
                        self.analyze('Exception')

        # print(recomplited)
        return recomplited