import random, socket
from struct import pack, unpack
import struct


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
|                      Network Layer data                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

def get_localhost():
    """ Helper method to retrieve the localhost address and port """
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host_socket.connect(('8.8.8.8', 80))

    # Returns the localhost name: (IP Address, Port No.)
    localhost = host_socket.getsockname()
    host_socket.close()

    return localhost

""" Set of constant fields """
HTTP_STATUS_CODE = 200
FORMAT = 'UTF-8'

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
TCP_CWND = 1

# * https://www.howtouselinux.com/post/tcp-flags#:~:text=TCP%20flags%20are%20various%20types,%2C%20fin%2C%20urg%2C%20psh.
""" TCP Flags """
FLAG_TCP_SYN = 1 # Synchronize (1: Sync Sequence numbers)
FLAG_TCP_ACK = 0 # Acknowledgement
FLAG_TCP_RST = 0 # Reset
FLAG_TCP_FIN = 0 # Finish
FLAG_TCP_URG = 0 # Urgent
FLAG_TCP_PSH = 0 # Push
TCP_FLAGS = FLAG_TCP_FIN + (FLAG_TCP_SYN << 1) + (FLAG_TCP_RST << 2) + (FLAG_TCP_PSH << 3) + (FLAG_TCP_ACK << 4) + (FLAG_TCP_URG << 5)    # << i: 2^i


""" IP Header fields """
# Convert IP addr dotted-quad string into 32 bit binary format
# * https://pythontic.com/modules/socket/inet_aton
IP_VERSION = 4
IP_HEADER_LEN = 5
IP_TOS = 0
IP_DGRAM_LEN = 20     # Start with IHL -> 5 words -> 20B + DATA Length (not known yet)
IP_ID = 54321
IP_TTL = 255
IP_PROTOCOL = socket.IPPROTO_TCP
IP_CHECKSUM = 0
IP_SRC_ADDRESS = socket.inet_aton(get_localhost()[0])
IP_DEST_ADDRESS = socket.inet_aton('')    # TODO: Extract Dest IP addr from the input argument URL
IP_PADDING = 0
IP_VER_HEADER_LEN = (IP_VERSION << 4) + IP_HEADER_LEN

""" IP Flags """
# TODO: Remove other flags except FRAG_OFFSET if not needed
FLAG_IP_RSV = 0
FLAG_IP_DTF = 0
FLAG_IP_MRF = 0
FLAG_IP_FRAG_OFFSET = 0
IP_FLAGS = (FLAG_IP_RSV << 7) + (FLAG_IP_DTF << 6) + (FLAG_IP_MRF << 5) + (FLAG_IP_FRAG_OFFSET)


""" Header formats """
# '!' - Network packet order
TCP_HEADER_FORMAT = '!HHLLBBHHH'
TCP_HEADER_SEGMENT_FORMAT = '!HHLLBBH'
PSEUDO_IP_HEADER_FORMAT = '!4s4sBBH'

# IP_HEADER_FORMAT = '!BBHHHBB'
# IP_HEADER_SEGMENT_FORMAT = '!4s4s'
IP_HEADER_FORMAT = '!BBHHHBBH4s4s'

# TODO: Start with IP Header information (P Data packing)
""" IP and TCP header field keys """
KEYS_TCP_FIELDS = ['src_port', 'dest_port', 'seq_num', 'ack_num', 'data_offset', 'flags', 'adv_window', 'checksum', 'urgent_ptr']
KEYS_IP_FIELDS = ['vhl', 'tos', 'total_len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr', 'version', 'header_len', 'frag_offset']


def compute_header_checksum(header_data):
    """ Helper method to calculate checksum """
    ''' Refereced from Suraj Singh, Bitforestinfo '''
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

def validate_header_checksum(packet_checksum, tcp_fields, tport_layer_packet, tcp_options, payload):
    """
    Helper method to verify TCP checksum
    """
    tcp_header = pack(
        TCP_HEADER_FORMAT,
        tcp_fields['src_port'], tcp_fields['dest_port'], tcp_fields['seq_num'], tcp_fields['ack_num'], tcp_fields['data_offset'], tcp_fields['flags'], tcp_fields['adv_window'], tcp_fields['checksum'], tcp_fields['urgent_ptr']
    ) + tcp_options  # TCP Options wasn't unpacked hence, no need to be packed again

    tcp_segment_length = len(tport_layer_packet)    # Already contains payload
    pseudo_ip_header = pack(
        PSEUDO_IP_HEADER_FORMAT,
        IP_SRC_ADDRESS, IP_DEST_ADDRESS, IP_PADDING, IP_PROTOCOL, tcp_segment_length
    )

    # Calculate Checksum by taking into account TCP header, TCP body and Pseudo IP header
    # ? Do I need to create TCP headers again to compute checksum
    return (packet_checksum == compute_header_checksum(tcp_header + payload.encode(FORMAT) + pseudo_ip_header))

def validate_ip_header_checksum(packet_checksum, ip_headers: dict):
    """
    Helper method to verify IP checksum
    """
    temp_ip_header = pack(
        IP_HEADER_FORMAT,
        ip_headers['vhl'], ip_headers['tos'], ip_headers['total_len'], ip_headers['id'], ip_headers['flags'], ip_headers['ttl'], ip_headers['protocol'], IP_CHECKSUM, ip_headers['src_addr'], ip_headers['dest_addr']
    )

    checksum = compute_header_checksum(temp_ip_header)

    return (checksum == packet_checksum)

# ? Check if we can split pack and re-pack functions for TCP fields
def pack_tcp_fields(seq_num: int, ack_num: int, flags: int, adv_window: int, payload: str):
    """
    Helper method to instantiate TCP fields: Takes in TCP fields as params that do not remain constant and pack with the data
        1. param: seq_num - sequence number of the current packet
        2. param: ack_num - acknowledgement number of last ACKed packet
        3. param: flags - flags that will be changed (SYN, ACK, FIN)
        4. param: adv_window - current advertised window of the receiver # ? Re-evaluate whether we need it
        5. param: data - payload to be send over the raw socket connection
        6. return: Data packet with the TCP header added on top of the payload (data)
    """
    temp_tcp_header = pack(
        TCP_HEADER_FORMAT,
        TCP_SOURCE_PORT, TCP_DEST_PORT, seq_num, ack_num, TCP_DATA_OFFSET, flags, adv_window, TCP_CHECKSUM, TCP_URGENT_PTR
    )

    tcp_segment_length = len(temp_tcp_header) + len(payload)

    ''' Checksum of the TCP is calculated by taking into account TCP header, TCP body and Pseudo IP header
        * Cannot correctly guess the IP header size from Transport layer
        * Calculate checksum using part of the IP header info that will remain unchanged in every packet
        * Pseudo IP Header fields (in order):
            1. IP of Source and Destination
            2. Padding/Placeholder (8 bits)
            3. Protocol (type of protocol)
            4. TCP/UDP Segment length
        * Only used for TCP Checksum calculation, discarded later and not sent to the Network layer
    '''
    pseudo_ip_header = pack(
        PSEUDO_IP_HEADER_FORMAT,
        IP_SRC_ADDRESS, IP_DEST_ADDRESS, IP_PADDING, IP_PROTOCOL, tcp_segment_length
    )

    # Calculate Checksum by taking into account TCP header, TCP body and Pseudo IP header
    checksum = compute_header_checksum(temp_tcp_header + payload.encode(FORMAT) + pseudo_ip_header)

    # Repack TCP header
    tcp_header = pack(
        TCP_HEADER_FORMAT,
        TCP_SOURCE_PORT, TCP_DEST_PORT, seq_num, ack_num, TCP_DATA_OFFSET, TCP_FLAGS, adv_window, checksum, TCP_URGENT_PTR
    ) # prev change: + pack('H', checksum) + pack('!H', TCP_URGENT_PTR)

    tcp_packet = tcp_header + payload.encode(FORMAT)
    return tcp_packet

def unpack_tcp_fields(tport_layer_packet):
    """
    Helper method to unpack TCP fields: Takes in Transport layer packet as param and extracts the TCP header
        1. param: tport_layer_packet - Data from the Transport layer (TCP header + payload)
        2. return: a key-value table of the fields of the TCP header and the payload
    """
    # Extract header fields from packet - 5 words - 20B. After 20B - ip_payload
    tcp_header_fields = unpack(TCP_HEADER_FORMAT, tport_layer_packet[: 20])
    tcp_headers = dict(zip(KEYS_TCP_FIELDS, tcp_header_fields))

    # Validate presence of any TCP options
    # 1. Shift offset 4 bits from data offset field and get no. of words value
    options_offset = tcp_headers['data_offset'] >> 4
    tcp_options = None

    # If this offset is = 5 words means that Options and Padding fields are empty, so..
    if (options_offset > 5):    # There are options [0...40B max]
        # ? Extract MSS - WTF should I do with it?
        tcp_options = tport_layer_packet[20 : 4 * options_offset]

    payload = tport_layer_packet[4 * options_offset :]

    # Validate: if packet is headed towards the correct destination port
    if (tcp_headers['dest_port'] != TCP_SOURCE_PORT):
        # TODO: Exit gracefully
        pass

    # Validate: TCP packet checksum - compute checksum again and add with the tcp checksum - should be 0xffff
    if (not validate_header_checksum(tcp_headers['checksum'], tcp_headers, tport_layer_packet, tcp_options, payload)):
        # TODO: Throw some error or some shit
        pass

    # Return the TCP headers and payload
    return tcp_headers, payload

def pack_ip_fields(tport_layer_packet):
    """
    Helper method to wrap IP header around the TCP header and data: Takes in tcp packet as param.
        param: tcp_packet - packet from the Transport layer and the payload
        return: Network layer packet with the IP header wrapped around
    """
    # TODO: Calculate IP Checksum
    IP_CHECKSUM = 0
    # TODO add time seeder before rand
    IP_ID = random.randint(0, pow(2, 16) - 1)   # ID MAX: 65535
    IP_DGRAM_LEN = 20 + len(tport_layer_packet)

    ip_header = struct.pack(
        IP_HEADER_FORMAT,
        IP_VER_HEADER_LEN, IP_TOS, IP_DGRAM_LEN, IP_ID
    )

def unpack_ip_fields(net_layer_packet):
    """
    Helper method to unpack the IP fields from the transport layer packet.
        param: tport_layer_packet - the transport layer data wrapped with TCP and IP headers
        return: network layer packet containing TCP headers and payload
    """
    ip_header_fields = struct.unpack(
        IP_HEADER_FORMAT, net_layer_packet[:20]
    )
    ip_headers = dict(zip(KEYS_IP_FIELDS, ip_header_fields))

    ip_headers['version'] = (ip_headers['vhl'] >> 4)
    ip_headers['header_len'] = (ip_headers['vhl'] & 0x0f)
    ip_headers['frag_offset'] = (ip_headers['frag_offset'] & 0x1fff)

    options_offset = ip_headers['header_len'] >> 4
    ip_options = None
    # check for ip options
    if (ip_headers['header_len'] > 5):
        ip_options = net_layer_packet[20:4 * options_offset]

    payload = net_layer_packet[4 * options_offset:]

    if (ip_headers['dest_addr'] != IP_SRC_ADDRESS):
        # TODO exit
        pass

    # TODO validate ip checksum

    return ip_headers, payload

def get_ip(ip_byte):
    """
    Helper method to convert IP byte string to correct format.
        param: ip_byte - the byte string format of the IP address
        return: correct string format of IP address with '.' separators
    """
    return '.'.join(map(str, ip_byte))
