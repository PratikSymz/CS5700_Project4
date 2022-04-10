import random, socket
from struct import pack, unpack
from typing import Optional

import utils


class tcp:
    '''
        Data class for TCP fields and methods related to TCP header packing, unpacking and checksum verification
    '''

    ''' TCP Header fields '''
    SOURCE_PORT = random.randint(49152, 65535)
    DEST_PORT = 80
    SEQ_NUM = random.randint(0, pow(2, 32) - 1)     # sequence number of the current packet
    ACK_NUM = 0     # acknowledgement number of last ACKed packet
    DATA_OFFSET = 5     # (No. of words = No. of rows). Offset to show after where the data starts.
    ADV_WINDOW = 65535      # current advertised window of the receiver
    DEFAULT_CHECKSUM = 0
    URGENT_PTR = 0
    MSS = 1460
    OPTIONS = b''

    ''' 
    TCP Flags
        1. Finish: FLAG_FIN, 
        2. Synchronize: FLAG_SYN, 
        3. Reset: FLAG_RST, 
        4. Push: FLAG_PSH, 
        5. Acknowledgement: FLAG_ACK, 
        6. Urgent: FLAG_URG
    '''
    FLAGS = {"FLAG_FIN": 0, "FLAG_SYN": 0, "FLAG_RST": 0, "FLAG_PSH": 0, "FLAG_ACK": 0, "FLAG_URG": 0}

    ''' Header formats '''
    HEADER_FORMAT = '!HHLLBBHHH'

    ''' IP and TCP header field keys '''
    KEYS_FIELDS = ['src_port', 'dest_port', 'seq_num', 'ack_num', 'data_offset', 'flags', 'adv_window', 'checksum', 'urgent_ptr']
    
    @staticmethod
    def pack_tcp_fields(flags: int, payload: bytes):
        '''
            Function: pack_tcp_fields() - this method is responsible for instantiating the TCP fields. Evaluates checksum using the psuedo IP header
                to calculate the checksum, which is packed into the TCP header with the Options and Payload.
            Parameters:
                flags - flags that will be changed (SYN, ACK, FIN, FIN/ACK)
                payload - data (in bytes) to be sent over the socket connection
            Returns: Transport layer packet with the TCP header wrapped over the payload
        '''
        # Create temporary tcp headers
        temp_tcp_header = pack(
            tcp.HEADER_FORMAT,
            tcp.SOURCE_PORT, tcp.DEST_PORT, tcp.SEQ_NUM, tcp.ACK_NUM, tcp.DATA_OFFSET << 4, flags, tcp.ADV_WINDOW, tcp.DEFAULT_CHECKSUM, tcp.URGENT_PTR
        ) + tcp.OPTIONS

        tcp_segment_length = len(temp_tcp_header) + len(payload)

        # Build the pseudo IP header
        pseudo_ip_header = pack(
            ip.PSEUDO_HEADER_FORMAT,
            ip.SRC_ADDRESS, ip.DEST_ADDRESS, ip.PADDING, ip.PROTOCOL, tcp_segment_length
        )

        # Calculate Checksum by taking into account TCP header, TCP body and Pseudo IP header
        check = pseudo_ip_header + temp_tcp_header + payload
        checksum = utils.compute_header_checksum(check)

        # Repack TCP header
        tcp_header = pack(
            tcp.HEADER_FORMAT,
            tcp.SOURCE_PORT, tcp.DEST_PORT, tcp.SEQ_NUM, tcp.ACK_NUM, tcp.DATA_OFFSET << 4, flags, tcp.ADV_WINDOW, checksum, tcp.URGENT_PTR
        )

        tport_layer_packet = tcp_header + tcp.OPTIONS + payload
        
        return tport_layer_packet

    @staticmethod
    def unpack_tcp_fields(tport_layer_packet: bytes):
        '''
            Function: unpack_tcp_fields() - this method takes in the Transport layer packet as parameter and extracts 
                the TCP headers and the payload
            Parameters:
                tport_layer_packet - data (in bytes) of the transport layer packet containing the TCP headers and the payload
            Returns: the parsed TCP headers (key-value pairs) and the payload
        '''
        # Extract header fields from packet
        tcp_header_fields = unpack(tcp.HEADER_FORMAT, tport_layer_packet[ :20])
        tcp_headers = dict(zip(tcp.KEYS_FIELDS, tcp_header_fields))

        # Validate: if packet is headed towards the correct destination port
        # No need to verify TCP fields - return
        if (tcp_headers["dest_port"] != tcp.SOURCE_PORT):
            return False

        # Validate presence of any TCP options
        # 1. Shift offset 4 bits from data offset field and get no. of words value
        tcp.DATA_OFFSET = tcp_headers["data_offset"] >> 4

        # If this offset is = 5 words means that Options and Padding fields are empty, so..
        if (tcp.DATA_OFFSET > 5):    # There are options [0...40B max]
            tcp.OPTIONS = tport_layer_packet[20 : 4 * tcp.DATA_OFFSET]
            tcp.MSS = unpack('!H', tcp.OPTIONS[0:4][2: ])[0]
        else:
            tcp.OPTIONS = b''

        payload = tport_layer_packet[4 * tcp.DATA_OFFSET: ]

        # Validate: TCP packet checksum - compute checksum again
        # Checksum error - Corrupted packet - receive retransmission
        if (not tcp.validate_header_checksum(tcp_headers["checksum"], tcp_headers, tport_layer_packet, tcp.OPTIONS, payload)):
            return False

        # Return the TCP headers and payload
        return tcp_headers, payload

    @staticmethod
    def validate_header_checksum(packet_checksum: bytes, tcp_fields: dict, tport_layer_packet: bytes, tcp_options: bytes, payload: bytes):
        '''
            Function: validate_header_checksum() - this method takes in the tcp fields from the received packet as input along 
                with the options and the payload and calculates the checksum which is compared against the received checksum
            Parameters:
                packet_checksum - checksum of the packet received from server
                tcp_fields - key-value pairs of the TCP header fields
                tport_layer_packet - data (in bytes) of the transport layer packet containing the TCP headers and the payload
                tcp_options - the TCP options received from the packet
                payload - the payload of the received packet
            Returns: whether the calculate checksum is same as the received checksum (bool)
        '''
        temp_tcp_header = pack(
            tcp.HEADER_FORMAT, 
            tcp_fields["src_port"], tcp_fields["dest_port"], tcp_fields["seq_num"], tcp_fields["ack_num"], tcp_fields["data_offset"], tcp_fields["flags"], tcp_fields["adv_window"], tcp.DEFAULT_CHECKSUM, tcp_fields["urgent_ptr"]
        ) + tcp_options  # TCP Options wasn't unpacked hence, no need to be packed again

        tcp_segment_length = len(tport_layer_packet)    # Already contains payload

        # Recalculate psuedo IP header
        pseudo_ip_header = pack(
            ip.PSEUDO_HEADER_FORMAT,
            ip.SRC_ADDRESS, ip.DEST_ADDRESS, ip.PADDING, ip.PROTOCOL, tcp_segment_length
        )

        # Calculate Checksum by taking into account TCP header, TCP body and Pseudo IP header
        return (packet_checksum == utils.compute_header_checksum(pseudo_ip_header + temp_tcp_header + payload))


class ip:
    '''
        Data class for IP fields and methods related to IP header packing, unpacking and checksum verification
    '''

    ''' IP Header fields '''
    # Convert IP addr dotted-quad string into 32 bit binary format
    VERSION = 4
    HEADER_LEN = 5
    TOS = 0
    DGRAM_LEN = 4 * HEADER_LEN     # Start with IHL -> 5 words -> 20B + DATA Length (not known yet)
    ID = 0
    TTL = 255
    PROTOCOL = socket.IPPROTO_TCP
    DEFAULT_CHECKSUM = 0
    SRC_ADDRESS: Optional[bytes] = None
    DEST_ADDRESS: Optional[bytes] = None
    PADDING = 0
    VER_HEADER_LEN = (VERSION << 4) + HEADER_LEN
    
    ''' IP Flags '''
    FLAG_RSV = 0
    FLAG_DTF = 0
    FLAG_MRF = 0
    FLAG_FRAG_OFFSET = 0
    FLAGS = (FLAG_RSV << 7) + (FLAG_DTF << 6) + (FLAG_MRF << 5) + FLAG_FRAG_OFFSET

    ''' Header formats '''
    PSEUDO_HEADER_FORMAT = '!4s4sBBH'
    HEADER_FORMAT = '!BBHHHBBH4s4s'

    KEYS_FIELDS = ['vhl', 'tos', 'total_len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr', 'version', 'header_len', 'frag_offset']

    @staticmethod
    def pack_ip_fields(tport_layer_packet: bytes):
        '''
            Function: pack_ip_fields() - this method is responsible for instantiating the IP fields. Evaluates checksum using the IP header
                to calculate the checksum, which is wrapped around the TCP packet
            Parameters:
                tport_layer_packet - data (in bytes) of the transport layer packet containing the TCP headers and the payload
            Returns: Network layer packet with the IP headers wrapped over the TCP headers and the payload
        '''
        ip.ID = random.randint(0, 65535)   # ID MAX: 65535
        ip.DGRAM_LEN = 4 * ip.HEADER_LEN + len(tport_layer_packet)

        temp_ip_header = pack(
            ip.HEADER_FORMAT,
            ip.VER_HEADER_LEN, ip.TOS, ip.DGRAM_LEN, ip.ID, ip.FLAGS, ip.TTL, ip.PROTOCOL, ip.DEFAULT_CHECKSUM, ip.SRC_ADDRESS, ip.DEST_ADDRESS
        )

        # Compute the packet checksum
        checksum = utils.compute_header_checksum(temp_ip_header)

        # Repack IP Header with the checksum and the TCP packet
        net_layer_packet = pack(
            ip.HEADER_FORMAT,
            ip.VER_HEADER_LEN, ip.TOS, ip.DGRAM_LEN, ip.ID, ip.FLAGS, ip.TTL, ip.PROTOCOL, checksum, ip.SRC_ADDRESS, ip.DEST_ADDRESS
        ) + tport_layer_packet

        return net_layer_packet

    @staticmethod
    def unpack_ip_fields(net_layer_packet: bytes):
        '''
            Function: unpack_ip_fields() - this method takes in the Network layer packet as parameter and extracts 
                the IP headers and the Transport layer packet which contain the TCP headers and the payload
            Parameters:
                net_layer_packet - data (in bytes) of the network layer packet containing the IP, TCP headers and the payload
            Returns: the parsed IP headers (key-value pairs) and the Transport layer packet
        '''
        # Unpack the IP headers
        ip_header_fields = unpack(ip.HEADER_FORMAT, net_layer_packet[ :20])
        ip_headers = dict(zip(ip.KEYS_FIELDS, ip_header_fields))

        # Only want to process packets from the project server
        # No need to verify IP fields - return
        if (ip_headers["src_addr"] != ip.DEST_ADDRESS):
            return False

        # Extract the version and the header length
        ip_headers["version"] = (ip_headers["vhl"] >> 4)
        ip_headers["header_len"] = (ip_headers["vhl"] & 0x0F)

        # The IP header payload
        tport_layer_packet = net_layer_packet[20: ]

        # Verify IP fields
        if (ip_headers["dest_addr"] != ip.SRC_ADDRESS):
            return False

        if (ip_headers["version"] != ip.VERSION):
            return False

        if (ip_headers["protocol"] != ip.PROTOCOL):
            return False

        if (not ip.validate_header_checksum(ip_headers["checksum"], ip_headers)):
            return False
        
        # Return the IP headers and Transport layer packet
        return ip_headers, tport_layer_packet

    @staticmethod
    def validate_header_checksum(packet_checksum: bytes, ip_headers: dict):
        '''
            Function: validate_header_checksum() - this method takes in the ip fields from the received packet as input and 
                calculates the checksum which is compared against the received checksum
            Parameters:
                packet_checksum - checksum of the packet received from server
                ip_headers - key-value pairs of the IP header fields
            Returns: whether the calculate checksum is same as the received checksum (bool)
        '''
        temp_ip_header = pack(
            ip.HEADER_FORMAT,
            ip_headers["vhl"], ip_headers["tos"], ip_headers["total_len"], ip_headers["id"], ip_headers["flags"], ip_headers["ttl"], ip_headers["protocol"], ip.DEFAULT_CHECKSUM, ip_headers["src_addr"], ip_headers["dest_addr"]
        )

        # Calculate checksum
        checksum = utils.compute_header_checksum(temp_ip_header)

        return (checksum == packet_checksum)
