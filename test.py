import utils
from headers import tcp, ip

FLAG_ACK = utils.concat_tcp_flags(utils.set_ack_bit(tcp.FLAGS))

print(FLAG_ACK)