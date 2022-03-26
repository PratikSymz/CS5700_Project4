import random, socket, struct


""" 
                        IP HEADER
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

# ? https://networklessons.com/cisco/ccie-routing-switching-written/tcp-header
""" 
                        TCP HEADER
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

""" Set of constant fields """
HTTP_STATUS_CODE = 200

""" TCP Header fields """
# * https://www.quora.com/When-using-a-localhost-how-many-ports-are-there
# * https://stackoverflow.com/questions/21253474/source-port-vs-destination-port
TCP_SOURCE_PORT = random.randint(0, pow(2, 16) - 1)
TCP_DEST_PORT = 80
TCP_SEQ_NUM = random.randint(0, pow(2, 32) - 1)
TCP_ACK_NUM = 0
TCP_DATA_OFFSET = 5  # (No. of words = No. of rows). Offset to show after where the data starts. # ? https://networkengineering.stackexchange.com/questions/39272/what-is-data-offset-and-its-uses-in-tcp-header
TCP_ADV_WINDOW = 5840  # TCP header value allocated for window size: two bytes long. Highest numeric value for a receive window is 65,535 bytes.
TCP_CHECKSUM = 0
TCP_URGENT_PTR = 0

# * https://www.howtouselinux.com/post/tcp-flags#:~:text=TCP%20flags%20are%20various%20types,%2C%20fin%2C%20urg%2C%20psh.
""" TCP Flags """
FLAG_TCP_SYN = 1 # Synchronize (1: Sync Sequence numbers)
FLAG_TCP_ACK = 0 # Acknowledgement
FLAG_TCP_RST = 0 # Reset
FLAG_TCP_FIN = 0 # Finish
FLAG_TCP_URG = 0 # Urgent
FLAG_TCP_PSH = 0 # Push
TCP_FLAGS = FLAG_TCP_FIN + (FLAG_TCP_SYN << 1) + (FLAG_TCP_RST << 2) + (FLAG_TCP_PSH << 3) + (FLAG_TCP_ACK << 4) + (FLAG_TCP_URG << 5)    # << i: 2^i

""" TCP Header formats """
TCP_HEADER_FORMAT = '!HHLLBBHHH'


''' CheckSum of the TCP is calculated by taking into account TCP header, TCP body and Pseudo IP header
    * Cannot correctly guess the IP header size from Transport layer
    * Calculate checksum using part of the IP header info that will remain unchanged in every packet
    * Pseudo IP Header fields:
        1. IP of Source and Destination
        2. TCP/UDP Segment length
        3. Protocol (type of protocol)
        4. Padding (8 bits)
    * Only used for TCP Checksum calculation, discarded later and not sent to the Network layer
'''

""" Helper method to calculate checksum """
''' Refereced from Suraj Singh, Bitforestinfo '''
def calc_header_checksum(header_data):
    binary_checksum = 0

    # Loop taking two characters at a time
    for i in range(0, len(header_data), 2):
        if (i == len(header_data) - 1):
            binary_checksum += ord(header_data[i])
        else:
            binary_checksum += ord(header_data[i]) + (ord(header_data[i + 1]) << 8)

    # Compute 1's complement
    binary_checksum += (binary_checksum >> 16)
    return ~binary_checksum & 0xffff

""" Helper method to retrieve the localhost address and port """
def get_localhost():
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host_socket.connect(('8.8.8.8', 80))
    
    # Returns the localhost name: (IP Address, Port No.)
    return host_socket.getsockname()

""" Helper method to instantiate TCP fields """
def pack_tcp_fields(seq_num: int, ack_num: int, adv_window: int, data: str):
    tcp_header = struct.pack(
        TCP_HEADER_FORMAT, 
        TCP_SOURCE_PORT, TCP_DEST_PORT, seq_num, ack_num, TCP_DATA_OFFSET, TCP_FLAGS, adv_window, TCP_CHECKSUM, TCP_URGENT_PTR
    )