import socket, sys, os, argparse

import utils
from headers import ip, tcp


class RawSocket:
    def __init__(self):
        ''' Extract the argument url and destination hostname '''
        self.arg_url = sys.argv[-1]
        self.host_url = utils.get_destination_url(self.arg_url)[1]

        ''' Set of constant fields '''
        self.TIMEOUT = 60     # TCP Retransmission Timeout: 1 minute
        self.BUFFER_SIZE = 65535    # MAX packet length
        self.EMPTY_PAYLOAD = b''
        self.FORMAT = 'utf-8'
        self.HTTP_STATUS_CODE = 200
        self.SOURCE_CLIENT = 'client'
        self.SOURCE_SERVER = 'server'
        
        ''' Constant field representing the default congestion window size '''
        self.CWND = 1

        ''' Set of constant fields for keeping track of count of retransmissions '''
        self.RETRANSMIT_CTR = 0
        self.RETRANSMIT_LMT = 3

        ''' Set of constant fields for the TCP flags for header verification '''
        self.FLAG_SYN = utils.concat_tcp_flags(utils.set_syn_bit(tcp.FLAGS))
        self.FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(tcp.FLAGS))
        self.FLAG_FIN = utils.concat_tcp_flags(utils.set_fin_bits(tcp.FLAGS))
        self.FLAG_FIN_ACK = utils.concat_tcp_flags(utils.set_fin_ack_bits(tcp.FLAGS))
        
        ''' Instantiate the IP Header Source and Destination addresses '''
        ip.SRC_ADDRESS = socket.inet_aton(utils.get_localhost_addr())
        ip.DEST_ADDRESS = socket.inet_aton(socket.gethostbyname(self.host_url))

        # Set the packet destination address
        self.destination = (socket.gethostbyname(self.host_url), tcp.DEST_PORT)

        try:
            # Raw socket setup
            # Setup Sender side socket (to Server)
            self.sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            # Setup Receiver side socket (to Localhost from Server)
            self.receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # Set receiver socket timeout
            self.receiver_socket.settimeout(self.TIMEOUT)

        except socket.error as socket_error:
            # Can't connect with socket
            sys.exit("Can't connect with socket! Timeout " + "\n")


    def run(self):
        '''
            Function: run() - this method is responsible for firstly initiating the TCP three-way handshake. Next, it sends a 
                GET request to the server. After that, it will manage the sequence numbers for all the packets it receives 
                from the server, while maintaning the congestion control mechanism. It receives all packets and saves it 
                in a dictionary. Lastly, it concatenates the payload in the correct order of sequence numbers and saves it 
                in a file and closes the connection.
            Parameters: none
            Returns: none
        '''
        # Drop outgoing TCP RST packets
        os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

        # Extract the parameter url
        arg_url = sys.argv[1]

        # Initiate TCP handshake
        self.init_tcp_handshake()

        # Build the GET request 
        url, host_url = utils.get_destination_url(arg_url)
        request_payload = utils.build_GET_request(url, host_url).encode(self.FORMAT)

        # Send the GET request to the server
        self.send_packet(self.FLAG_ACK, request_payload)

        # Payload sent, update SEQ_NUM
        tcp.SEQ_NUM += len(request_payload)

        # Maintain a TCP Segment dict to keep track of out of order packets
        tcp_segments = {}

        # Receive incoming packet information
        ip_headers, tcp_headers, payload = {}, {}, self.EMPTY_PAYLOAD
        while True:
            # Receive Network layer packet
            ip_headers, tcp_headers, payload = self.receive_ack_packet(self.FLAG_ACK)

            # Parse TCP headers (flags) for FIN message
            # FIN flag received from the Server - close connection and send FIN/ACK to the server
            if (tcp_headers["flags"] & self.FLAG_FIN > 0):
                # Once server FIN received, break from loop
                tcp.SEQ_NUM = tcp_headers["ack_num"]
                tcp.ACK_NUM = tcp_headers["seq_num"] + 1  # Do +1 to ACK the FIN flag
               
                # Initiate connection shutdown through server request
                self.close_connection(self.SOURCE_SERVER)
                break
            
            # Packet transmitted from the server - handle all cases and update SEQ and ACK nums
            if (tcp_headers["flags"] & self.FLAG_ACK > 0 and tcp_headers["seq_num"] not in tcp_segments and len(payload) > 0):
                # Compare the Seq no. we're maintaining with the transmitted Ack no.
                if (tcp.SEQ_NUM == tcp_headers["ack_num"]):    # ! and tcp.ACK_NUM == tcp_headers["seq_num"]
                    # Add payload for the specific SEQ_NUM
                    tcp_segments[tcp_headers["seq_num"]] = payload
                    # Update Sequence numbers
                    tcp.SEQ_NUM = tcp_headers["ack_num"]
                    tcp.ACK_NUM = tcp_headers["seq_num"] + len(payload)

                    # Update the Client's advertized window
                    tcp.ADV_WINDOW = tcp_headers["adv_window"]

                    # Update congestion window
                    self.CWND = utils.set_congestion_control(self.CWND, tcp.ADV_WINDOW)

                    # Send ACK for the packet received and update ACK number of client
                    self.send_packet(self.FLAG_ACK, self.EMPTY_PAYLOAD)

                else:
                    # Packet dropped - send ACK again
                    self.CWND = utils.set_congestion_control(self.CWND, tcp.ADV_WINDOW, True)
                    self.send_packet(self.FLAG_ACK, self.EMPTY_PAYLOAD)

        # Sort the TCP segments based on SEQ_NUM and concatenate the payload
        tcp_segments_inorder = sorted(tcp_segments.items())
        appl_layer_packet = self.EMPTY_PAYLOAD

        for _, data_segment in tcp_segments_inorder:
            appl_layer_packet += data_segment

        # Tear down connection after all data has been received
        self.close_connection(self.SOURCE_CLIENT)

        # Get response content
        raw_headers, raw_body = utils.parse_response(appl_layer_packet.decode(self.FORMAT))
        # Check HTTP Status Code from the raw HTML data
        response_code = utils.get_response_code(raw_headers)

        if (response_code == self.HTTP_STATUS_CODE):
            headers = utils.parse_headers(raw_headers)

            # Write content to file
            filename = utils.get_filename(arg_url)
            utils.write_to_file(filename, raw_body)
        
        else:
            # Exit program
            sys.exit('HTTP Error! Response NOT 200')


    def init_tcp_handshake(self):
        '''
            Function: init_tcp_handshake() - this method is responsible for initiating the TCP three-way handshake: SYN, SYN/ACK, ACK.
                    The SEQ and ACK numbers are validated based on the handshake values. The first SYN bit is sent, next the 
                    SYN/ACK is received and the sequence numbers are updated accordingly. Lastly, the ACK bit is sent to establish the connection.
            Parameters: none
            Returns: none
        '''
        # 1. Send packet from Network layer with TCP SYN = 1 and payload as Null: SYN<1, 0> bit 1
        self.send_packet(self.FLAG_SYN, self.EMPTY_PAYLOAD)
        
        # Receive incoming packet information
        ip_headers, tcp_headers, payload = self.receive_ack_packet(self.FLAG_SYN)

        # Update the Client's advertized window
        tcp.ADV_WINDOW = tcp_headers["adv_window"]

        # Send final ACK and finish handshake
        # At end of SYN/ACK <1S, 2C>
        if (tcp.SEQ_NUM == tcp_headers["ack_num"] - 1):
            # Complete handshake procedure
            # ACK received for Client side, update SEQ_NUM and send ACK to Server
            tcp.SEQ_NUM = tcp_headers["ack_num"]

            # Update ACK for Server side
            tcp.ACK_NUM = tcp_headers["seq_num"]

            # Set TCP flags for final ACK message (for Server)
            FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(tcp.FLAGS))

            # Send final handshake message
            tcp.ACK_NUM += 1
            self.send_packet(FLAG_ACK, self.EMPTY_PAYLOAD)

        else:
            self.close_connection(self.SOURCE_CLIENT)
            sys.exit("3-Way Handshake failed!!!" + "\n")


    def send_packet(self, flags: int, payload: bytes):
        '''
            Function: send_packet() - this method is responsible for sending Network layer packets to the project server. It segments the payload into 
                    chunks of size dependent on the congestion window. Each chunk is wrapped in TCP and IP headers and sent to the 
                    project server until all segments have been transferred.
            Parameters:
                flags - the TCP flags to set when sending packet
                payload - the payload (in bytes) to be sent
            Returns: none
        '''
        # Maintain a current pointer and a data buffer to send the amount of data defined by the CWND
        curr_ptr = 0
        # Set the congestion window
        self.CWND = utils.set_congestion_control(self.CWND, tcp.ADV_WINDOW)
        # Set the next pointer
        next_ptr = curr_ptr + (self.CWND * tcp.MSS)
        
        data_buffer = payload
        segments_transferred = False

        # Start sending data
        while not segments_transferred:
            if (len(data_buffer) > next_ptr - curr_ptr):
                # Set the payload buffer limit
                send_buffer = data_buffer[curr_ptr : next_ptr]

                # Update the current and the next pointers
                data_buffer = data_buffer[next_ptr: ]
                curr_ptr = next_ptr
                next_ptr = curr_ptr + (self.CWND * tcp.MSS)
            
            else:
                # Last data segment
                # The payload left is less than the limit - send all remaining
                send_buffer = data_buffer[curr_ptr: ]
                segments_transferred = True
            
            tport_layer_packet = tcp.pack_tcp_fields(flags, send_buffer)
            net_layer_packet = ip.pack_ip_fields(tport_layer_packet)

            # Send packet from the Network layer to the server
            try:
                self.sender_socket.sendto(net_layer_packet, self.destination)
            except socket.error as socket_error:
                sys.exit('Sender Socket Error!')


    def receive_ack_packet(self, flags: int):
        '''
            Function: receive_ack_packet() - this method is responsible for receiving Network layer packets with the ACK bit set from the project server.
                    Furthermore, if the receiver socket timeouts, it enters retrasmission mode, where it retransmits upto three times. 
                    Once, the retransmission counter is over, it stops and exits.
            Parameters:
                flags - the TCP flags to expect in an ACK packet
            Returns: the IP headers, TCP headers and the packet payload
        '''
        ip_headers, tcp_headers, payload = {}, {}, self.EMPTY_PAYLOAD
        
        while True:
            # Receive Network layer packet from the server
            try:
                net_layer_packet = self.receiver_socket.recv(self.BUFFER_SIZE)

            except socket.timeout:
                # Check if retransmissions happened more than the limit
                if (self.RETRANSMIT_CTR < self.RETRANSMIT_LMT):
                    # Increment Retransmit counter
                    self.RETRANSMIT_CTR += 1

                    # Socket timeout, reset CWND and enter slow start mode to retransmit
                    self.CWND = utils.set_congestion_control(self.CWND, tcp.ADV_WINDOW, True)
                    self.send_packet(flags, self.EMPTY_PAYLOAD)
                    continue

                else:
                    self.close_connection(self.SOURCE_CLIENT)
                    sys.exit('TCP Retransmission limit reached!')

            # Parse Network layer packet
            try:
                # Packet received is not from the project server
                if (isinstance(ip.unpack_ip_fields(net_layer_packet), bool)):
                    continue
                
                ip_headers, tport_layer_packet = ip.unpack_ip_fields(net_layer_packet)  # type: ignore

            except socket.error as socket_error:
                sys.exit("Invalid data received! Timeout " + "\n")

            # Parse Transport layer packet
            try:
                # Packet received is not from the correct port no.
                if (isinstance(tcp.unpack_tcp_fields(tport_layer_packet), bool)):
                    continue

                tcp_headers, payload = tcp.unpack_tcp_fields(tport_layer_packet)  # type: ignore

            except socket.error as socket_error:
                sys.exit("Invalid data received! Timeout " + "\n")

            # Check for ACK flag in packet
            if (tcp_headers["flags"] & self.FLAG_ACK > 0):
               # Once server ACK received, break from loop
               break

        return ip_headers, tcp_headers, payload


    def close_connection(self, source: str):
        '''
            Function: close_connection() - this method is responsible for tearing down the connection. The connection is closed based on the source parameter.
                    If the source is the SERVER, i.e., the server has initiated the connection teardown and has send a packet with the FIN flag, the program 
                    sends a FIN_ACK and closes the connection.
                    However, if the source is CLIENT, which means that the client has received all data and has to tear down the connection. In this case, we 
                    first send a packet with the FIN/ACK bits set to the server, the server responds with a FIN/ACK and finally, we send the ACK packet to 
                    acknowledge the FIN of the server and the connection is terminated.
            Parameters: 
                source - the source initiating the connection teardown request (Client or Server)
            Returns: none
        '''
        if (source == self.SOURCE_SERVER):
            print('Server-side shutdown!')
            self.send_packet(self.FLAG_FIN_ACK, self.EMPTY_PAYLOAD)
        
        if (source == self.SOURCE_CLIENT):
            print('Client-side shutdown!')
            self.send_packet(self.FLAG_FIN_ACK, self.EMPTY_PAYLOAD)
            self.receive_ack_packet(self.FLAG_FIN_ACK)
            self.send_packet(self.FLAG_ACK, self.EMPTY_PAYLOAD)


if __name__ == "__main__":
    ''' Script argument parser '''
    parser = argparse.ArgumentParser('Project 4: Raw Sockets')

    # Store URL from terminal
    parser.add_argument("URL", type=str, action="store", help="URL")    # Store value from input

    args = parser.parse_args()
    raw_socket = RawSocket()
    raw_socket.run()