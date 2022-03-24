
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
TCP_SOURCE_PORT = 0
TCP_DEST_PORT = 0
TCP_SEQ_NUM = 0
TCP_ACK_NUM = 0
TCP_OFFSET = 0
TCP_ADV_WINDOW = 0
TCP_CHECKSUM = 0

# https://www.howtouselinux.com/post/tcp-flags#:~:text=TCP%20flags%20are%20various%20types,%2C%20fin%2C%20urg%2C%20psh.
""" TCP Flags """
TCP_SYN = 0 # Synchronize
TCP_ACK = 0 # Acknowledgement
TCP_RST = 0 # Reset
TCP_FIN = 0 # Finish
TCP_URG = 0 # Urgent
TCP_PSH = 0 # Push

""" Helper method for IP and TCP Headers """
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

""" Helper method to create  """

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

""" Helper method to instantiate TCP fields """
def init_tcp_fields(source_port, dest_port, seq_num, ack_seq_num, header_len):
    pass