import socket, sys, utils


class RawSocket:
    # Sender and receiver sockets
    sender_socket, receiver_socket = socket.socket(), socket.socket()

    ''' Set of contstant fields for TCP header '''
    IP_TIMEOUT = 3 * 60     # IP Timeout: 3 minutes
    BUFFER_SIZE = pow(2, 16) - 1    # MAX IP packet length
    BIT_SYN_ACK = 0x12      # Hex value of 010010 where SYN/ACK are both 1
    BIT_ACK = 0x10      # Hex value of 010000 where ACK is 1
    BIT_FIN_ACK = 0x11      # Hex value of 010001 where ACK and FIN are both 1 for closing connection

    def __init__(self):
        try:
            # Raw socket setup
            # ? Check for IPv6 later. For that we need socket.AF_INET6. Starting with IPv4 now
            sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            receiver_socket.settimeout(RawSocket.IP_TIMEOUT)

        except socket.error as socket_error:
            # Can't connect with socket
            # utils.close_stream(WebCrawler.client_socket_ssl)
            print("Socket creation error: " + str(socket_error))
            sys.exit("Can't connect with socket! Timeout " + "\n")

    @staticmethod
    def send_packet(arg_url: str, seq_num: int, ack_num: int, flags: int, adv_window: int, payload: str):
        ''' Helper method to send IP packet to the project server '''
        tport_layer_packet = utils.pack_tcp_fields(seq_num, ack_num, flags, adv_window, payload)
        net_layer_packet = utils.pack_ip_fields(tport_layer_packet)

        dest_addr, dest_port = socket.gethostbyname(utils.get_destination_url(arg_url)[1]), utils.TCP_DEST_PORT
        RawSocket.sender_socket.sendto(net_layer_packet, (dest_addr, dest_port))

    @staticmethod
    def init_tcp_handshake():
        ''' Helper method to initiate the TCP three-way handshake: SYN, SYN/ACK, ACK '''
        # Set TCP flags - SYN = 1 (by default), others all 0
        utils.TCP_FLAGS = utils.set_tcp_flags()

        # 1. Send packet from Network layer with TCP SYN = 1 and payload as Null: SYN<1, 0> bit 1
        RawSocket.send_packet('', utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, utils.TCP_FLAGS, utils.TCP_ADV_WINDOW, '')

        while True:
            ''' Continue receiving packets until handshake second packet SYN/ACK<> is received '''
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

            # Parse TCP headers (flags) for ACK message: SYN/ACK<1, 1> bit both 1
            if (tcp_headers["flags"] & RawSocket.BIT_SYN_ACK == RawSocket.BIT_SYN_ACK):
                # Once server ACK received, break from loop and send third SYN + payload to complete the handshake
                break
        
        # Send final ACK and finish handshake
        # At end of SYN/ACK <1S, 2C>
        if (tcp_headers["seq_num"] == tcp_headers["ack_num"] - 1):
            # Complete handshake procedure
            # ACK received for Client side, update SEQ_NUM and send ACK to Server
            utils.TCP_SEQ_NUM += 1

            # Update ACK for Server side
            utils.TCP_ACK_NUM = tcp_headers["seq_num"] + 1

            # Set TCP flags for final ACK message (for Server)
            utils.TCP_FLAGS = RawSocket.BIT_ACK

            # Send final handshake message
            RawSocket.send_packet('', utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, utils.TCP_FLAGS, utils.TCP_ADV_WINDOW, '')

        else:
            sys.exit("3-Way Handshake failed!!!" + "\n")

    @staticmethod
    def close_connection():
        ''' Helper method to close connection with the server based on TCP flags '''
        ''' https://medium.com/@cspsprotocols247/tcp-connenction-termination-what-is-fin-fin-ack-rst-and-rst-ack-1a5032d346fb '''
        # Set TCP flags - FIN/ACK<1, 1>
        utils.TCP_FLAGS = RawSocket.BIT_FIN_ACK

        # 1. Send packet from Network layer with TCP FIN = 1 and ACK = 1 for payload: FIN/ACK<1, 1>
        RawSocket.send_packet('', utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, utils.TCP_FLAGS, utils.TCP_ADV_WINDOW, '')

        while True:
            ''' Continue receiving packets until FIN/ACK<> message is received '''
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
            if (tcp_headers["flags"] & RawSocket.BIT_FIN_ACK == RawSocket.BIT_FIN_ACK):
                # Once server FIN/ACK received, break from loop
                break

        # utils.TCP_ACK_NUM = tcp_headers["ack_num"]
        if (tcp_headers["seq_num"] == tcp_headers["ack_num"] - 1):
            # Complete connection teardown
            # ACK received for Client side, update SEQ_NUM
            utils.TCP_SEQ_NUM = tcp_headers["seq_num"]

            # Update ACK for Server side
            utils.TCP_ACK_NUM = tcp_headers["seq_num"] + 1
            
            # Send final ACK to Server to terminate connection
            utils.TCP_FLAGS = RawSocket.BIT_ACK

            # Send the final ACK to the server to terminate the connection
            RawSocket.send_packet('', utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, utils.TCP_FLAGS, utils.TCP_ADV_WINDOW, '')

if __name__ == "__main__":
    RawSocket()