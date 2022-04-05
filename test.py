import socket

host_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
host_socket.connect(('8.8.8.8', 80))
    
# Returns the localhost name: (IP Address, Port No.)
localhost = host_socket.getsockname()
host_socket.close()

print(bytes(socket.IPPROTO_TCP))
test = b'\x00\x00\x00\x00\x00\x00'
print (bytes(0x06))