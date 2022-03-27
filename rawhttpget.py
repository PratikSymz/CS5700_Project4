import socket, sys

class RawSocket:
    # Sender and receiver sockets
    sender_socket, receiver_socket = None, None

    def __init__(self):
        try:
            # Raw socket setup
            # ? Check for IPv6 later. For that we need socket.AF_INET6. Starting with IPv4 now
            sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            # TODO: Add Socket timeout (60s as per project spec)

        except socket.error as socket_error:
            # Can't connect with socket
            # utils.close_stream(WebCrawler.client_socket_ssl)
            print("Socket creation error: " + str(socket_error))
            sys.exit("Can't connect with socket! Timeout " + "\n")