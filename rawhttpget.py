import argparse
import socket, sys, utils, os, time


class RawSocket:
    def __init__(self):
        # Command line args
        # self.arg_url = sys.argv[0]    # ? do we need this here or only in run()
        # Sender and receiver sockets
        self.sender_socket, self.receiver_socket = socket.socket(), socket.socket()

        ''' Set of contstant fields for TCP header '''
        self.TIMEOUT = 60     # TCP Retransmission Timeout: 1 minute
        self.BUFFER_SIZE = pow(2, 16) - 1    # MAX packet length

        # BIT_SYN_ACK = 0x12      # Hex value of 010010 where SYN/ACK are both 1
        # BIT_ACK = 0x10      # Hex value of 010000 where ACK is 1
        # BIT_FIN_ACK = 0x11      # Hex value of 010001 where ACK and FIN are both 1 for closing connection
        
        self.SERVER_URL = ''
        self.CWND = 1

        try:
            # Raw socket setup
            # Setup Sender side socket (To Server)
            sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            print('created sender\n')
            dest_addr, dest_port = socket.gethostbyname(utils.get_destination_url(self.SERVER_URL)[1]), utils.TCP_DEST_PORT
            print('addr:', dest_addr, 'port:', dest_port)
            sender_socket.connect((dest_addr, dest_port))
            print('sender socket connected\n')

            # Setup Receiver side socket (To Localhost)
            receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            print('created receiver\n')
            src_addr = utils.get_localhost_addr()
            src_port = utils.get_localhost_port(receiver_socket, src_addr)
            print('addr:', src_addr, 'port:', src_port)
            receiver_socket.bind((src_addr, src_port))
            print('bind receiver socket\n')
            receiver_socket.settimeout(self.TIMEOUT)

        except socket.error as socket_error:
            # Can't connect with socket
            # utils.close_stream(WebCrawler.client_socket_ssl)
            print("Socket creation error: " + str(socket_error))
            sys.exit("Can't connect with socket! Timeout " + "\n")

    def send_packet(self, seq_num: int, ack_num: int, flags: int, adv_window: int, payload: str):
        ''' 
        Helper method to send Network layer packet to the project server 
        Sending of packets will depend on the Congestion Window. We start with 1 and increase it further
        '''
        # Maintain a current pointer and a data buffer to send the amount of data defined by the CWND
        curr_ptr = 0
        next_ptr = curr_ptr + (self.CWND * utils.TCP_MSS)
        data_buffer = payload
        segments_transferred = False

        #self.CWND = utils.set_congestion_control(self.CWND, utils.TCP_ADV_WINDOW)

        # Start sending data
        while not segments_transferred:
            if (len(data_buffer) > next_ptr - curr_ptr):
                # Set the payload buffer limit
                send_buffer = data_buffer[curr_ptr : next_ptr]

                # Update the current and the next pointers
                data_buffer = data_buffer[next_ptr: ]
                curr_ptr = next_ptr
                next_ptr = curr_ptr + (self.CWND * utils.TCP_MSS)
            
            else:   # Last data segment
                # The payload left is less than the limit - send all remaining
                send_buffer = data_buffer[curr_ptr: ]
                segments_transferred = True

            tport_layer_packet = utils.pack_tcp_fields(seq_num, ack_num, flags, adv_window, send_buffer)
            net_layer_packet = utils.pack_ip_fields(tport_layer_packet)

            # Send packet from the Network layer to the server
            self.sender_socket.sendall(net_layer_packet)


    def receive_packet(self, flag_type: bytes):
        ''' Helper method to receive packets from the project server to the Network layer '''
        ip_headers, tcp_headers, payload = {}, {}, b''
        curr_time = time.perf_counter()
        
        while True:
            # TODO: Add timeout check
            if (time.perf_counter() - curr_time > self.TIMEOUT):
                pass
                # ? Either return or closeConnection(). Pretty sure have to do retransmission
            # Receive Network layer packet from the server
            try:
                net_layer_packet = self.receiver_socket.recv(self.BUFFER_SIZE)

            except socket.timeout as socket_timeout:
                # Socket timeout, reset CWND and enter slow start mode to retransmit
                self.CWND = utils.set_congestion_control(self.CWND, utils.TCP_MSS, True)
                # ? Restart sending??
                # print("Socket timeout: " + str(socket_timeout))
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

    def init_tcp_handshake(self):
        ''' Helper method to initiate the TCP three-way handshake: SYN, SYN/ACK, ACK '''
        # Set TCP flags - SYN = 1 (by default), others all 0
        FLAG_SYN = utils.concat_tcp_flags(utils.set_syn_bit(utils.FLAGS_TCP))

        # 1. Send packet from Network layer with TCP SYN = 1 and payload as Null: SYN<1, 0> bit 1
        self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_SYN, utils.TCP_ADV_WINDOW, '')
        
        # Receive incoming packet information
        ip_headers, tcp_headers, payload = self.receive_packet(FLAG_SYN)

        # Update the Client's advertized window
        utils.TCP_ADV_WINDOW = tcp_headers["adv_window"]

        # Send final ACK and finish handshake
        # At end of SYN/ACK <1S, 2C>
        if (tcp_headers["seq_num"] == tcp_headers["ack_num"] - 1):
            # Complete handshake procedure
            # ACK received for Client side, update SEQ_NUM and send ACK to Server
            # utils.TCP_SEQ_NUM += 1
            utils.TCP_SEQ_NUM = tcp_headers["ack_num"]

            # Update ACK for Server side
            utils.TCP_ACK_NUM = tcp_headers["seq_num"]

            # Set TCP flags for final ACK message (for Server)
            FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(utils.FLAGS_TCP))

            # Send final handshake message
            utils.TCP_ACK_NUM = utils.TCP_ACK_NUM + 1
            self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_ACK, utils.TCP_ADV_WINDOW, '')

        else:
            # TODO: Close connection from client side - Server side complete
            sys.exit("3-Way Handshake failed!!!" + "\n")

    def close_connection(self):
        ''' Helper method to close connection with the server based on TCP flags '''
        ''' https://medium.com/@cspsprotocols247/tcp-connenction-termination-what-is-fin-fin-ack-rst-and-rst-ack-1a5032d346fb '''
        # Set TCP flags - FIN/ACK<1, 1>
        FLAG_FIN_ACK = utils.concat_tcp_flags(utils.set_fin_ack_bits(utils.FLAGS_TCP))

        # 1. Send packet from Network layer with TCP FIN = 1 and ACK = 1 for payload: FIN/ACK<1, 1>
        self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_FIN_ACK, utils.TCP_ADV_WINDOW, '')

        # Receive incoming packet information
        ip_headers, tcp_headers, payload = self.receive_packet(FLAG_FIN_ACK)
        
        # Update the Client's advertized window
        utils.TCP_ADV_WINDOW = tcp_headers["adv_window"]

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
            self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_ACK, utils.TCP_ADV_WINDOW, '')
        else:
            print("Unable to close connection!!!" + "\n")

    def run(self):
        # Drop outgoing TCP RST packets
        os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

        arg_url = sys.argv[0]

        # Start TCP handshake
        self.init_tcp_handshake()

        # Send get request for webpage
        url, host_url = utils.get_destination_url(arg_url)
        request_payload = utils.build_GET_request(url, host_url)
        FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(utils.FLAGS_TCP))
        FLAG_FIN = utils.concat_tcp_flags(utils.set_fin_bits(utils.FLAGS_TCP))
        FLAG_FIN_ACK = utils.concat_tcp_flags(utils.set_fin_ack_bits(utils.FLAGS_TCP))
        
        self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_ACK, utils.TCP_ADV_WINDOW, request_payload) # utils.IP_DEST_ADDRESS, 

        # Payload sent, update SEQ_NUM
        utils.TCP_SEQ_NUM += len(request_payload)

        # Maintain a TCP Segment dict to keep track of out of order packets
        tcp_segments = {}

        # TODO: Start receiving info
        # Receive incoming packet information
        ip_headers, tcp_headers, payload = {}, {}, b''
        while True:
            # Receive Network layer packet from the server
            try:
                net_layer_packet = self.receiver_socket.recv(self.BUFFER_SIZE)

            except socket.timeout as socket_timeout:
                # TODO: Exit system
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

            # Parse TCP headers (flags) for FIN message
            # TODO: Recheck logic for SERVER and CLIENT FIN separately
            if (tcp_headers["flags"] & FLAG_FIN == FLAG_FIN):
                # Once server FIN received, break from loop
                utils.TCP_SEQ_NUM = tcp_headers["ack_num"]
                utils.TCP_ACK_NUM = tcp_headers["seq_num"] + 1  # Do +1 to ACK the FIN flag
                # TODO: Send FIN_ACK to server since it closed the connection
                self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_FIN_ACK, utils.TCP_ADV_WINDOW, '')
                break
            
            # Normal packet transmission
            if (tcp_headers["flags"] & FLAG_ACK > 0 and tcp_headers["seq_num"] not in tcp_segments and len(payload) > 0):
                # Compare the Seq no. we're maintaining with the transmitted Ack no.
                if (utils.TCP_SEQ_NUM == tcp_headers["ack_num"]):    # and utils.TCP_ACK_NUM == tcp_headers["ack_num"]
                    # Add payload for the specific SEQ_NUM
                    tcp_segments[tcp_headers["seq_num"]] = payload
                    # Update Sequence numbers
                    utils.TCP_SEQ_NUM = tcp_headers["ack_num"]
                    utils.TCP_ACK_NUM = tcp_headers["seq_num"] + len(payload)

                    # Update the Client's advertized window
                    utils.TCP_ADV_WINDOW = tcp_headers["adv_window"]

                    # Update congestion window
                    self.CWND = utils.set_congestion_control(self.CWND, utils.TCP_MSS, False)

                    # Send ACK for the packet received and update ACK number of client
                    self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_ACK, utils.TCP_ADV_WINDOW, '')

                else:
                    # Packet dropped - send ACK again
                    self.CWND = utils.set_congestion_control(self.CWND, utils.TCP_MSS, True)
                    self.send_packet(utils.TCP_SEQ_NUM, utils.TCP_ACK_NUM, FLAG_ACK, utils.TCP_ADV_WINDOW, '')

        # Sort the TCP segments based on SEQ_NUM and concatenate the payload
        tcp_segments_inorder = sorted(tcp_segments.items())
        appl_layer_packet = b''

        for _, data_segment in tcp_segments_inorder:
            appl_layer_packet += data_segment
        
        # TODO: Extract HTTP header info, parse and save into file
        # * Final data in appl_layer_packet

        # Get file path name
        file_path = utils.get_filepath(arg_url)
        # ip_headers, tcp_headers, response_data = self.receive_packet(b'')
        # Get response content
        # TODO check if content is correct
        headers, body = utils.parse_response(appl_layer_packet.decode(utils.FORMAT))

        # Write content to file
        filename = utils.get_filename(arg_url)
        utils.write_to_file(arg_url, body)

        # Close socket connections
        self.close_connection()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("URL", type=str, action="store", help="URL")
    args = parser.parse_args()
    RawSocket()