class FLC:
    """
    Frequently used Letter Combinations
    """

    def __init__(self):
        super(FLC, self).__init__()
        self.__load_combinations()

    def __load_combinations(self):
        self.data = {
            'to {} for': '1',
            'to {} to': '2',
            'to {} 1': '3',
            '1 {} 1': '4',
        }


class Packet(FLC):
    """
    Encrypted data transmission method
    """

    def __init__(self, msg: str):
        """
        Standard method of data transmission
        :param msg: Message to transmits
        """
        super(Packet, self).__init__()

        self.special_packet_key = 'SIP21:'
        self.format(msg)

    def reverse(self, msg: str, key: str = ""):
        full_key = key.replace("SIP21:", '')
        index_key_part = ''
        data_key_part = ''

        addition_value = 0
        for elem in full_key.split('@'):
            if elem != '':
                index_key_part += str(int(elem.split('-')[0]) + addition_value)
                data_key_part += str(int(elem.split('-')[1]) + addition_value)
                addition_value += 1

        answer = msg.split(' ')

        for index in range(len(index_key_part)):
            print(index_key_part[index])
            answer.insert(int(index_key_part[index]) - 1, '~')
            answer.insert(int(index_key_part[index]) + 1, '~')

        final_answer = ''
        for a in answer:
            final_answer += a + ' '
        return final_answer

    def format(self, msg: str):
        related_data = msg.split(' ')

        def a(arr: list):
            for i in range(len(arr)):
                for comb in self.data:
                    s_comb = comb.split(' ')
                    try:
                        if arr[i].lower() == s_comb[0] and arr[i + 2].lower() == s_comb[2]:
                            del arr[i]
                            del arr[i + 1]

                            self.special_packet_key += str(i + 1) + '-' + self.data.get(comb) + '@'
                            a(arr)
                    except IndexError:
                        pass

        a(related_data)

        # construct new message
        answer = ''
        for word in related_data:
            answer += word + ' '
        print("Message:", answer)
        print("Key:", self.special_packet_key)

        print(self.reverse(answer, self.special_packet_key))
