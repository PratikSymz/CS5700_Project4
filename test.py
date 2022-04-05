import utils, socket

# data_ip = b"45000592464540002a069ddfcc2cc03c0a6ed06a"
data_ip = bytes.fromhex("4500003c000040002a06e97acc2cc03c0a6ed06a")
#data_tcp = b"\x00\x50\xc6\xb7\x62\xa0\x1b\x46\xa4\x26\x9c\x94\xa0\x12\x71\x20\x99\x5e\x00\x00\x02\x04\x05\x6a\x04\x02\x08\x0a\xbe\xb9\x5c\xb5\xbb\x68\x79\xf8\x01\x03\x03\x07"

data_tcp = bytes.fromhex("0050c6b762a01b46a4269c94a0127120995e00000204056a0402080abeb95cb5bb6879f801030307")

# print(utils.unpack_ip_fields(data_ip))
# print(utils.unpack_tcp_fields(data_tcp))
IP_SRC_ADDRESS = socket.inet_aton('204.44.192.60')
IP_DEST_ADDRESS = socket.inet_aton('10.110.208.106')
# print(IP_SRC_ADDRESS, IP_DEST_ADDRESS)