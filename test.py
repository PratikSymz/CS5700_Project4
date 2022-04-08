import socket

print(socket.inet_ntoa(b'\n\x00\x02\x02'))
print(socket.inet_ntoa(b'\n\x00\x02\x0f'))