from email import header
import socket, sys, os, time, argparse, random

import utils
from headers import ip, tcp

class RawSocket:
    def __init__(self):
        ''' Extract the argument url and destination hostname '''
        self.arg_url = sys.argv[-1]
        self.host_url = utils.get_destination_url(self.arg_url)[1]

        ''' Set of constant fields '''
        self.TIMEOUT = 60     # TCP Retransmission Timeout: 1 minute
        self.BUFFER_SIZE = pow(2, 16) - 1    # MAX packet length
        self.EMPTY_PAYLOAD = b''
        self.FORMAT = 'utf-8'
        
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

        try:
            # Raw socket setup
            # Setup Sender side socket (To Server)
            self.sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # Set the destination address
            self.destination = (socket.gethostbyname(self.host_url), tcp.DEST_PORT)

            # Setup Receiver side socket (To Localhost)
            self.receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # Set the localhost address
            src_addr = utils.get_localhost_addr()
            src_port = random.randint(1024, 65530) #utils.get_localhost_port(self.receiver_socket, src_addr)
            source = (src_addr, src_port)
            # ! How to receive data
            self.receiver_socket.settimeout(self.TIMEOUT)

        except socket.error as socket_error:
            # Can't connect with socket
            print("Socket creation error: " + str(socket_error))
            sys.exit("Can't connect with socket! Timeout " + "\n")

    def send_packet(self, flags: int, payload: bytes):
        '''
            Function: 
                send_packet - this method is responsible for sending Network layer packets to the project server. It segments the payload into 
                    chunks of size dependent on the congestion window. Each chunk is wrapped in TCP and IP headers and sent to the 
                    project server until all segments have been transferred.
            Parameters:
                flags - the TCP flags to set when sending packet
                payload - the payload (in bytes) to be sent
            Returns: none
        '''
        print('Setting Send params!')
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
            print('Checking send conditions!')
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
            
            print('Wrapping payload!')
            tport_layer_packet = tcp.pack_tcp_fields(flags, send_buffer)
            net_layer_packet = ip.pack_ip_fields(tport_layer_packet)

            # Send packet from the Network layer to the server
            print('Sending packet to server!')
            try:
                self.sender_socket.sendto(net_layer_packet, self.destination)
            except socket.error:
                sys.exit('Socket Send Error!')

    def receive_ack_packet(self, flags: int):
        '''
            Function: 
                receive_ack_packet - this method is responsible for receiving Network layer packets with the ACK bit set from the project server.
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
                net_layer_packet = self.receiver_socket.recv(self.BUFFER_SIZE)  # ! .recvfrom(buff)
                print('Receiving!')

            except socket.timeout:
                print('Receive Timeout!')
                # Check if retransmissions happened more than the limit
                if (self.RETRANSMIT_CTR < self.RETRANSMIT_LMT):
                    # Increment Retransmit counter
                    self.RETRANSMIT_CTR += 1

                    # Socket timeout, reset CWND and enter slow start mode to retransmit
                    self.CWND = utils.set_congestion_control(self.CWND, tcp.ADV_WINDOW, True)
                    self.send_packet(flags, self.EMPTY_PAYLOAD)
                    print('Retransmitting! Count: ', self.RETRANSMIT_CTR)
                    continue

                else:
                    self.close_connection('CLIENT')
                    sys.exit('TCP Handshake failed!')

            # Parse Network layer packet
            try:
                ip_headers, tport_layer_packet = ip.unpack_ip_fields(net_layer_packet)
                print('Packet received!')
                print('Parsing IP!')

            except socket.error as socket_error:
                print("Invalid IP packet: " + str(socket_error))
                sys.exit("Invalid data received! Timeout " + "\n")

            # Parse Transport layer packet
            try:
                tcp_headers, payload = tcp.unpack_tcp_fields(tport_layer_packet)
                print('Parsing TCP!')

            except socket.error as socket_error:
                print("Invalid TCP packet: " + str(socket_error))
                sys.exit("Invalid data received! Timeout " + "\n")

            # Check for ACK flag in Handshake and Close connection processes
            if (tcp_headers["flags"] & self.FLAG_ACK > 0):
               # Once server ACK received, break from loop
               print('ACK Received!')
               break

        return ip_headers, tcp_headers, payload

    def init_tcp_handshake(self):
        ''' Helper method to initiate the TCP three-way handshake: SYN, SYN/ACK, ACK '''
        '''
            Function: 
                receive_ack_packet - this method is responsible for receiving Network layer packets with the ACK bit set from the project server.
                    Furthermore, if the receiver socket timeouts, it enters retrasmission mode, where it retransmits upto three times. 
                    Once, the retransmission counter is over, it stops and exits.
            Parameters:
                flags - the TCP flags to expect in an ACK packet
            Returns: the IP headers, TCP headers and the packet payload
        '''

        # 1. Send packet from Network layer with TCP SYN = 1 and payload as Null: SYN<1, 0> bit 1
        self.send_packet(self.FLAG_SYN, self.EMPTY_PAYLOAD)
        print('TCP Handshake Initiated!')
        
        # Receive incoming packet information
        ip_headers, tcp_headers, payload = self.receive_ack_packet(self.FLAG_SYN)

        # Update the Client's advertized window
        tcp.ADV_WINDOW = tcp_headers["adv_window"]

        # Send final ACK and finish handshake
        # At end of SYN/ACK <1S, 2C>
        if (tcp_headers["seq_num"] == tcp_headers["ack_num"] - 1):
            # Complete handshake procedure
            # ACK received for Client side, update SEQ_NUM and send ACK to Server
            # utils.TCP_SEQ_NUM += 1
            tcp.SEQ_NUM = tcp_headers["ack_num"]

            # Update ACK for Server side
            tcp.ACK_NUM = tcp_headers["seq_num"]

            # Set TCP flags for final ACK message (for Server)
            FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(tcp.FLAGS))

            # Send final handshake message
            tcp.ACK_NUM += 1
            print('Sending Final Handshake!')
            self.send_packet(FLAG_ACK, self.EMPTY_PAYLOAD)
            print('Handshake complete!')

        else:
            self.close_connection('CLIENT')
            sys.exit("3-Way Handshake failed!!!" + "\n")

    def close_connection(self, source: str):
        ''' Helper method to close connection with the server based on TCP flags '''
        if (source == 'SERVER'):
            print('Server-side closed!')
            self.send_packet(self.FLAG_FIN_ACK, self.EMPTY_PAYLOAD)
        
        if (source == 'CLIENT'):
            print('Client-side shutdown!')
            self.send_packet(self.FLAG_FIN_ACK, self.EMPTY_PAYLOAD)
            self.receive_ack_packet(self.FLAG_FIN_ACK)
            self.send_packet(self.FLAG_ACK, self.EMPTY_PAYLOAD)

    def run(self):
        # Drop outgoing TCP RST packets
        os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")

        arg_url = sys.argv[1]

        # Start TCP handshake
        self.init_tcp_handshake()

        # Send get request for webpage
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
            # TODO: Recheck logic for SERVER and CLIENT FIN separately
            # FIN flag received from the Server - close connection and send FIN/ACK to the server
            if (tcp_headers["flags"] & self.FLAG_FIN > 0):
                # Once server FIN received, break from loop
                tcp.SEQ_NUM = tcp_headers["ack_num"]
                tcp.ACK_NUM = tcp_headers["seq_num"] + 1  # Do +1 to ACK the FIN flag
                self.close_connection('SERVER')
                break
            
            # Packet transmitted from the server - handle all cases and update SEQ and ACK nums
            if (tcp_headers["flags"] & self.FLAG_ACK > 0 and tcp_headers["seq_num"] not in tcp_segments and len(payload) > 0):
                # Compare the Seq no. we're maintaining with the transmitted Ack no.
                if (tcp.SEQ_NUM == tcp_headers["ack_num"]):    # and utils.TCP_ACK_NUM == tcp_headers["ack_num"]
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

        # Get file path name
        # file_path = utils.get_filepath(arg_url)
        # Get response content
        # TODO check if content is correct
        raw_headers, raw_body = utils.parse_response(appl_layer_packet.decode(self.FORMAT))
        headers = utils.parse_headers(raw_headers)

        # Write content to file
        filename = utils.get_filename(arg_url)
        utils.write_to_file(filename, raw_body)

        # Close socket connections
        self.close_connection('CLIENT')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("URL", type=str, action="store", help="URL")
    args = parser.parse_args()
    raw_socket = RawSocket()
    raw_socket.run()