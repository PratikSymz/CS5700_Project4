import random, socket
from struct import pack, unpack
from typing import Optional

import utils


class tcp:
    ''' TCP Header fields '''
    SOURCE_PORT = 50871
    DEST_PORT = 80
    SEQ_NUM = random.randint(0, pow(2, 32) - 1)
    ACK_NUM = 0
    DATA_OFFSET = 5  # (No. of words = No. of rows). Offset to show after where the data starts.
    ADV_WINDOW = 65535  # TCP header value allocated for window size: two bytes long. Highest numeric value for a receive window is 65,535 bytes.
    DEFAULT_CHECKSUM = 0
    URGENT_PTR = 0
    MSS = 1500  #536
    OPTIONS = b''

    # SOURCE_PORT = 50871
    # DEST_PORT = 80
    # SEQ_NUM = 2753993875
    # ACK_NUM = 0
    # DATA_OFFSET = 11  # (No. of words = No. of rows). Offset to show after where the data starts.
    # ADV_WINDOW = 65535  # TCP header value allocated for window size: two bytes long. Highest numeric value for a receive window is 65,535 bytes.
    # DEFAULT_CHECKSUM = 0
    # URGENT_PTR = 0
    # MSS = 1460  #536
    # OPTIONS = bytes.fromhex('020405b4010303060101080abb6879f80000000004020000')

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
        Helper method to instantiate TCP fields: Takes in TCP fields as params that do not remain constant and pack with the data
            1. param: seq_num - sequence number of the current packet
            2. param: ack_num - acknowledgement number of last ACKed packet
            3. param: flags - flags that will be changed (SYN, ACK, FIN)
            4. param: adv_window - current advertised window of the receiver
            5. param: data - payload to be send over the raw socket connection
            6. return: Data packet with the TCP header added on top of the payload (data)
        '''
        temp_tcp_header = pack(
            tcp.HEADER_FORMAT,
            tcp.SOURCE_PORT, tcp.DEST_PORT, tcp.SEQ_NUM, tcp.ACK_NUM, tcp.DATA_OFFSET << 4, flags, tcp.ADV_WINDOW, tcp.DEFAULT_CHECKSUM, tcp.URGENT_PTR
        ) + tcp.OPTIONS

        tcp_segment_length = len(temp_tcp_header) + len(payload)

        pseudo_ip_header = pack(
            ip.PSEUDO_HEADER_FORMAT,
            ip.SRC_ADDRESS, ip.DEST_ADDRESS, ip.PADDING, ip.PROTOCOL, tcp_segment_length
        )

        # Calculate Checksum by taking into account TCP header, TCP body and Pseudo IP header
        check = pseudo_ip_header + temp_tcp_header + payload
        checksum = utils.compute_header_checksum(check)  # ! payload.encode(FORMAT)
        print('TCP Checksum: ', hex(checksum))

        # Repack TCP header
        tcp_header = pack(
            tcp.HEADER_FORMAT,
            tcp.SOURCE_PORT, tcp.DEST_PORT, tcp.SEQ_NUM, tcp.ACK_NUM, tcp.DATA_OFFSET << 4, flags, tcp.ADV_WINDOW, checksum, tcp.URGENT_PTR
        )

        tport_layer_packet = tcp_header
        # ! Check if needed - just add the Options - Default: b''
        if (len(tcp.OPTIONS) > 0):
            tport_layer_packet += tcp.OPTIONS
        tport_layer_packet += payload  # ! payload.encode(FORMAT)
        
        return tport_layer_packet

    @staticmethod
    def unpack_tcp_fields(tport_layer_packet: bytes):
        '''
        Helper method to unpack TCP fields: Takes in Transport layer packet as param and extracts the TCP header
            1. param: tport_layer_packet - Data from the Transport layer (TCP header + payload)
            2. return: a key-value table of the fields of the TCP header and the payload
        '''
        # Extract header fields from packet - 5 words - 20B. After 20B - ip_payload
        tcp_header_fields = unpack(tcp.HEADER_FORMAT, tport_layer_packet[ :20])
        tcp_headers = dict(zip(tcp.KEYS_FIELDS, tcp_header_fields))
        print(tcp_headers)

        # Validate presence of any TCP options
        # 1. Shift offset 4 bits from data offset field and get no. of words value
        tcp.DATA_OFFSET = tcp_headers["data_offset"] >> 4

        # If this offset is = 5 words means that Options and Padding fields are empty, so..
        if (tcp.DATA_OFFSET > 5):    # There are options [0...40B max]
            tcp.OPTIONS = tport_layer_packet[20 : 4 * tcp.DATA_OFFSET]
            tcp.MSS = unpack('!H', tcp.OPTIONS[0:4][2: ])[0]

        payload = tport_layer_packet[4 * tcp.DATA_OFFSET: ]

        # Validate: if packet is headed towards the correct destination port
        print(tcp_headers["dest_port"], tcp.SOURCE_PORT)
        if (tcp_headers["dest_port"] != tcp.SOURCE_PORT):
            raise Exception('TCP: Invalid Dest. PORT!')

        # Validate: TCP packet checksum - compute checksum again and add with the tcp checksum - should be 0xffff
        if (not tcp.validate_header_checksum(tcp_headers["checksum"], tcp_headers, tport_layer_packet, tcp.OPTIONS, payload)):
            raise Exception('TCP: Invalid CHECKSUM!')

        # Return the TCP headers and payload
        print(payload)
        return tcp_headers, payload

    @staticmethod
    def validate_header_checksum(packet_checksum: bytes, tcp_fields: dict, tport_layer_packet: bytes, tcp_options: bytes, payload: bytes):
        ''' Helper method to verify TCP checksum '''
        temp_tcp_header = pack(
            tcp.HEADER_FORMAT, 
            tcp_fields["src_port"], tcp_fields["dest_port"], tcp_fields["seq_num"], tcp_fields["ack_num"], tcp_fields["data_offset"], tcp_fields["flags"], tcp_fields["adv_window"], tcp.DEFAULT_CHECKSUM, tcp_fields["urgent_ptr"]
        ) + tcp_options  # TCP Options wasn't unpacked hence, no need to be packed again

        # TODO: Check if during Checksum verification, should it be set to 0 or the actual value
        tcp_segment_length = len(tport_layer_packet)    # Already contains payload
        pseudo_ip_header = pack(
            ip.PSEUDO_HEADER_FORMAT,
            ip.SRC_ADDRESS, ip.DEST_ADDRESS, ip.PADDING, ip.PROTOCOL, tcp_segment_length
        )

        # Calculate Checksum by taking into account TCP header, TCP body and Pseudo IP header
        return (packet_checksum == utils.compute_header_checksum(pseudo_ip_header + temp_tcp_header + payload))


class ip:
    ''' IP Header fields '''
    # Convert IP addr dotted-quad string into 32 bit binary format
    VERSION = 4
    HEADER_LEN = 5
    TOS = 0
    DGRAM_LEN = 20     # Start with IHL -> 5 words -> 20B + DATA Length (not known yet)
    ID = 0
    TTL = 255
    PROTOCOL = socket.IPPROTO_TCP
    DEFAULT_CHECKSUM = 0
    SRC_ADDRESS: Optional[bytes] = None
    DEST_ADDRESS: Optional[bytes] = None
    PADDING = 0
    VER_HEADER_LEN = (VERSION << 4) + HEADER_LEN
    OPTIONS = b''

    # VERSION = 4
    # HEADER_LEN = 5
    # TOS = 0
    # DGRAM_LEN = 20     # Start with IHL -> 5 words -> 20B + DATA Length (not known yet)
    # ID = 0
    # TTL = 64
    # PROTOCOL = socket.IPPROTO_TCP
    # DEFAULT_CHECKSUM = 0
    # SRC_ADDRESS = bytes.fromhex('0a6ed06a') # socket.inet_aton('10.110.208.106')
    # DEST_ADDRESS = bytes.fromhex('cc2cc03c') # socket.inet_aton('204.44.192.60')
    # PADDING = 0
    # VER_HEADER_LEN = (VERSION << 4) + HEADER_LEN
    # OPTIONS = b''
    
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
        Helper method to wrap IP header around the TCP header and data: Takes in tcp packet as param.
            param: tcp_packet - packet from the Transport layer and the payload
            return: Network layer packet with the IP header wrapped around
        '''
        #ip.ID = random.randint(0, 65535)   # ID MAX: 65535
        ip.DGRAM_LEN = 20 + len(tport_layer_packet)

        temp_ip_header = pack(
            ip.HEADER_FORMAT,
            ip.VER_HEADER_LEN, ip.TOS, ip.DGRAM_LEN, ip.ID, ip.FLAGS, ip.TTL, ip.PROTOCOL, ip.DEFAULT_CHECKSUM, ip.SRC_ADDRESS, ip.DEST_ADDRESS
        )

        checksum = utils.compute_header_checksum(temp_ip_header)
        print('IP Checksum: ', hex(checksum))

        # Repack IP Header with the checksum
        net_layer_packet = pack(
            ip.HEADER_FORMAT,
            ip.VER_HEADER_LEN, ip.TOS, ip.DGRAM_LEN, ip.ID, ip.FLAGS, ip.TTL, ip.PROTOCOL, checksum, ip.SRC_ADDRESS, ip.DEST_ADDRESS
        ) + tport_layer_packet

        return net_layer_packet

    @staticmethod
    def unpack_ip_fields(net_layer_packet: bytes):
        '''
        Helper method to unpack the IP fields from the transport layer packet.
            param: tport_layer_packet - the transport layer data wrapped with TCP and IP headers
            return: network layer packet containing TCP headers and payload
        '''
        ip_header_fields = unpack(ip.HEADER_FORMAT, net_layer_packet[ :20])
        ip_headers = dict(zip(ip.KEYS_FIELDS, ip_header_fields))
        print(ip_headers)

        ip_headers["version"] = (ip_headers["vhl"] >> 4)
        ip_headers["header_len"] = (ip_headers["vhl"] & 0x0F)
        ip_headers["frag_offset"] = (ip_headers["flags"] & 0x1FFF)

        options_offset = ip_headers["header_len"] >> 4
        # check for ip options
        if (ip_headers["header_len"] > 5):
            ip.OPTIONS = net_layer_packet[20 : 4 * options_offset]

        # The IP header payload
        tport_layer_packet = net_layer_packet[4 * options_offset: ]

        # Verify IP fields
        if (ip_headers["dest_addr"] != ip.SRC_ADDRESS):
            raise Exception('IP: Invalid Dest. IP ADDR!')

        if (ip_headers["version"] != ip.VERSION):
            raise Exception('IP: Invalid NOT IPv4!')

        if (ip_headers["protocol"] != ip.PROTOCOL):
            raise Exception('IP: Invalid PROTOCOL!')

        # if (not ip.validate_header_checksum(ip_headers["checksum"], ip_headers)):
        #     raise Exception('IP: Invalid CHECKSUM!')
        
        # Return the IP headers and Transport layer packet
        return ip_headers, tport_layer_packet

    @staticmethod
    def validate_header_checksum(packet_checksum: bytes, ip_headers: dict):
        ''' Helper method to verify IP checksum '''
        temp_ip_header = pack(
            ip.HEADER_FORMAT,
            ip_headers["vhl"], ip_headers["tos"], ip_headers["total_len"], ip_headers["id"], ip_headers["flags"], ip_headers["ttl"], ip_headers["protocol"], ip.DEFAULT_CHECKSUM, ip_headers["src_addr"], ip_headers["dest_addr"]
        )

        checksum = utils.compute_header_checksum(temp_ip_header)
        print(checksum)

        return (checksum == packet_checksum)
