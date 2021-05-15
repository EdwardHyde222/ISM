from PacketExceptions import PacketExceptions


class Decrypt(PacketExceptions):
    def __init__(self):
        super().__init__()

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

    def decrypt(self, data: str) -> str:
        """
        Class of packet decrypter
        :param data: Packet that will be decrypted
        :return: Value of the packet
        """
        packet_value = ''
        # data = packet.encrypted_data

        for index in range(len(data)):
            # if data[index] in self.__static_combs or data[index] == ' ':
            #     packet_value += data[index]
            # else:
            for combo in self.__combinations:
                try:
                    complimented_letters = data[index] + data[index + 1] + data[index + 2]

                    if complimented_letters == self.__combinations.get(combo, ''):
                        res = dict((v, k) for k, v in self.__combinations.items())
                        packet_value += str(res.get(complimented_letters))
                        break
                except ValueError:
                    self.analyze('ValueError')
                except IndexError:
                    self.analyze('IndexError')
        return packet_value
