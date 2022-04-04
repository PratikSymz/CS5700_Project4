import socket, sys, utils


class RawSocket:
    # Sender and receiver sockets
    sender_socket, receiver_socket = socket.socket(), socket.socket()

    ''' Set of contstant fields for TCP header '''
    IP_TIMEOUT = 3 * 60     # IP Timeout: 3 minutes
    BUFFER_SIZE = pow(2, 16) - 1    # MAX IP packet length
    # BIT_SYN_ACK = 0x12      # Hex value of 010010 where SYN/ACK are both 1
    # BIT_ACK = 0x10      # Hex value of 010000 where ACK is 1
    # BIT_FIN_ACK = 0x11      # Hex value of 010001 where ACK and FIN are both 1 for closing connection

    SERVER_URL = ''

    def __init__(self):
        try:
            # Raw socket setup
            # Setup Sender side socket (To Server)
            sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            dest_addr, dest_port = socket.gethostbyname(utils.get_destination_url(RawSocket.SERVER_URL)[1]), utils.TCP_DEST_PORT
            sender_socket.connect((dest_addr, dest_port))

            # Setup Receiver side socket (To Localhost)
            receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            src_addr = utils.get_localhost_addr()
            src_port = utils.get_localhost_port(receiver_socket, src_addr)
            receiver_socket.bind((src_addr, src_port))
            receiver_socket.settimeout(RawSocket.IP_TIMEOUT)

        except socket.error as socket_error:
            # Can't connect with socket
            # utils.close_stream(WebCrawler.client_socket_ssl)
            print("Socket creation error: " + str(socket_error))
            sys.exit("Can't connect with socket! Timeout " + "\n")

    @staticmethod
    def send_packet(seq_num: int, ack_num: int, flags: int, adv_window: int, payload: str):
        ''' Helper method to send Network layer packet to the project server '''
        tport_layer_packet = utils.pack_tcp_fields(seq_num, ack_num, flags, adv_window, payload)
        net_layer_packet = utils.pack_ip_fields(tport_layer_packet)

        # Send packet from the Network layer to the server
        RawSocket.sender_socket.sendall(net_layer_packet)

    @staticmethod
    def receive_packet(flag_type: bytes):
        ''' Helper method to receive packets from the project server to the Network layer '''
        ip_headers, tcp_headers, payload = {}, {}, b''
        
        while True:
            # Receive Network layer packet from the server
            try:
                net_layer_packet = RawSocket.receiver_socket.recv(RawSocket.BUFFER_SIZE)

            except socket.timeout as socket_timeout:
                print("Socket timeout: " + str(socket_timeout))
                sys.exit("No data received! Timeout " + "\n")

            # Parse Network layer packet
            try:
                ip_headers, tport_layer_packet = utils.unpack_ip_fields(net_layer_packet)

            except socket.error as socket_error:
                print("Invalid IP packet: " + str(socket_error))
                sys.exit("Invalid data received! Timeout " + "\n")

            # Parse Transport layer packet
            try:
                tcp_headers, payload = utils.unpack_tcp_fields(tport_layer_packet)

            except socket.error as socket_error:
                print("Invalid TCP packet: " + str(socket_error))
                sys.exit("Invalid data received! Timeout " + "\n")

            # Parse TCP headers (flags) for FIN/ACK message: FIN/ACK<1, 1>
            if (tcp_headers["flags"] & flag_type == flag_type):
                # Once server FIN/ACK received, break from loop
                break

        return ip_headers, tcp_headers, payload

    @staticmethod
    def init_tcp_handshake():
        ''' Helper method to initiate the TCP three-way handshake: SYN, SYN/ACK, ACK '''
        # Set TCP flags - SYN = 1 (by default), others all 0
        FLAG_SYN = utils.concat_tcp_flags(utils.set_syn_bit(utils.FLAGS_TCP))

        # 1. Send packet from Network layer with TCP SYN = 1 and payload as Null: SYN<1, 0> bit 1
        RawSocket.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_SYN, utils.TCP_ADV_WINDOW, '')

        # Receive incoming packet information
        ip_headers, tcp_headers, payload = RawSocket.receive_packet(FLAG_SYN)

        # Send final ACK and finish handshake
        # At end of SYN/ACK <1S, 2C>
        if (tcp_headers["seq_num"] == tcp_headers["ack_num"] - 1):
            # Complete handshake procedure
            # ACK received for Client side, update SEQ_NUM and send ACK to Server
            utils.TCP_SEQ_NUM += 1

            # Update ACK for Server side
            utils.TCP_ACK_NUM = tcp_headers["seq_num"] + 1

            # Set TCP flags for final ACK message (for Server)
            FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(utils.FLAGS_TCP))

            # Send final handshake message
            RawSocket.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_ACK, utils.TCP_ADV_WINDOW, '')

        else:
            sys.exit("3-Way Handshake failed!!!" + "\n")

    @staticmethod
    def close_connection():
        ''' Helper method to close connection with the server based on TCP flags '''
        ''' https://medium.com/@cspsprotocols247/tcp-connenction-termination-what-is-fin-fin-ack-rst-and-rst-ack-1a5032d346fb '''
        # Set TCP flags - FIN/ACK<1, 1>
        FLAG_FIN_ACK = utils.concat_tcp_flags(utils.set_fin_ack_bits(utils.FLAGS_TCP))

        # 1. Send packet from Network layer with TCP FIN = 1 and ACK = 1 for payload: FIN/ACK<1, 1>
        RawSocket.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_FIN_ACK, utils.TCP_ADV_WINDOW, '')

        # Receive incoming packet information
        ip_headers, tcp_headers, payload = RawSocket.receive_packet(FLAG_FIN_ACK)

        # utils.TCP_ACK_NUM = tcp_headers["ack_num"]
        if (tcp_headers["seq_num"] == tcp_headers["ack_num"] - 1):
            # Complete connection teardown
            # ACK received for Client side, update SEQ_NUM
            utils.TCP_SEQ_NUM = tcp_headers["seq_num"]

            # Update ACK for Server side
            utils.TCP_ACK_NUM = tcp_headers["seq_num"] + 1
            
            # Send final ACK to Server to terminate connection
            FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(utils.FLAGS_TCP))

            # Send the final ACK to the server to terminate the connection
            RawSocket.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_ACK, utils.TCP_ADV_WINDOW, '')

if __name__ == "__main__":
    RawSocket()