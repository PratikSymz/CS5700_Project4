import utils
from headers import tcp, ip

tcp_header = tcp.pack_tcp_fields(tcp.flags, b'')
#ip_header = ip.pack_ip_fields(tcp_header)