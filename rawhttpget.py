

class RawSocket:
    # Sender and receiver sockets
    sender_socket, receiver_socket = None, None

    def __init__(self):

        try:
            # Raw socket setup
            sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        except:
            # Can't connect with socket
            # utils.close_stream(WebCrawler.client_socket_ssl)
            sys.exit("Can't connect with socket! Timeout " + "\n")


