import socket, sys, utils

class RawSocket:
    # Sender and receiver sockets
    sender_socket, receiver_socket = socket.socket(), socket.socket()

    def __init__(self):
        try:
            # Raw socket setup
            # ? Check for IPv6 later. For that we need socket.AF_INET6. Starting with IPv4 now
            self.sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # TODO: Add Socket timeout (60s as per project spec)

        except socket.error as socket_error:
            # Can't connect with socket
            # utils.close_stream(WebCrawler.client_socket_ssl)
            print("Socket creation error: " + str(socket_error))
            sys.exit("Can't connect with socket! Timeout " + "\n")

    """ Helper method to send IP packet to the project server """
    @staticmethod
    def send_packet(arg_url: str, seq_num: int, ack_num: int, flags: int, adv_window: int, payload: str):
        tport_layer_packet = utils.pack_tcp_fields(seq_num, ack_num, flags, adv_window, payload)
        net_layer_packet = utils.pack_ip_fields(tport_layer_packet)

        dest_addr, dest_port = socket.gethostbyname(utils.get_destination_url(arg_url)[1]), utils.TCP_DEST_PORT
        RawSocket.sender_socket.sendto(net_layer_packet, (dest_addr, dest_port))


if __name__ == "__main__":
    RawSocket()