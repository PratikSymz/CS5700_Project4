import utils
from headers import tcp, ip

flags = utils.concat_tcp_flags(utils.set_syn_bit(tcp.FLAGS))
tcp_header = tcp.pack_tcp_fields(flags, b'')
#ip_header = ip.pack_ip_fields(tcp_header)x