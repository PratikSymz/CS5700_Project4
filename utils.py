import socket


''' Set of constant fields for HTTP connection '''
HTTP_VERSION = 'HTTP/1.0'
HOST_NAME_HEADER = 'Host: '

def compute_header_checksum(header_data: bytes):
    '''
        Function: compute_header_checksum() - computes the header checksum for TCP/IP headers to send to the server
        Parameters:
            header_data - header information (in bytes)
        Returns: the header checksum value in bytes
    '''
    checksum = 0

    # Sum up 2 words at a time (16 bits)
    for i in range(0, len(header_data), 2):
        # Sum the value of each word
        if (i == len(header_data) - 1):
            checksum += header_data[i]
        else:
            checksum += header_data[i] + (header_data[i + 1] << 8)

    carry = (checksum & 0xffff) + (checksum >> 16)
    result = (~carry) & 0xffff

    # Interchange the bytes
    result = (result >> 8) | ((result & 0x00ff) << 8)
    return result

def set_congestion_control(cwnd: int, ssthresh: int, slow_start=False):
    '''
        Function: set_congestion_control() - sets the congestion window value for data transmission limit
        Parameters: 
            cwnd - the current congestion window, 
            ssthresh - the advertised window limit of the client, 
            slow_start - the flag to determine whether to reset congestion window and begin slow start
        Returns: the congestion window value
    '''
    cwnd_limit = 1000
    if slow_start:
        cwnd = 1
    else:
        # Where ssthresh is the ADV_WND (receiver) limit
        cwnd = min(cwnd * 2, cwnd_limit, ssthresh)

    return cwnd

def get_localhost_addr():
    '''
        Function: get_localhost_addr() - determines the localhost ip address by pinging to Google's primary DNS server
        Parameters: none
        Returns: the localhost ip address
    '''
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host_socket.connect(('8.8.8.8', 80))
    
    # returns the localhost name: (IP Address, Port No.)
    localhost = host_socket.getsockname()
    host_socket.close()

    return localhost[0]

def get_destination_url(arg_url: str):
    '''
        Function: get_destination_url() - extracts the destination address from the argument url
        Parameters: 
            arg_url - the argument url from the script
        Returns: the url without the 'http' header and the host url
    '''
    # Only support standard 'http' urls
    if (arg_url.startswith('https://')):
        raise Exception('Invalid URL!')
    
    url, host_url = '', ''
    if (arg_url.startswith('http://')):
        url = arg_url[7: ]

    if '/' in url:
        ptr = url.find('/')
        host_url = url[ :ptr]

    return url, host_url

def build_GET_request(url: str, host_url: str):
    '''
        Function: build_GET_request() - builds the HTTP GET request using the argument url
        Parameters: 
            url - the destination url with the paths
            host_url - the destination hostname
        Returns: the HTTP GET request
    '''
    message_lines = [
        'GET http://' + url + ' ' + HTTP_VERSION, 
        HOST_NAME_HEADER + host_url
    ]
    
    return '\r\n'.join(message_lines) + '\r\n\r\n'

def parse_response(http_response: bytes):
    '''
        Function: parse_response() - parses the response data from the GET request and returns the raw content of the response
        Parameters: 
            http_response - the http response received from server
        Returns: the raw headers and raw HTML body
    '''
    sections = http_response.split(b'\r\n\r\n')
    # sections[0] - raw Headers, sections[1] - raw HTML data
    # The response is only HTTP Headers (i.e., just after log in)
    if (len(sections) < 2):
        return sections[0], ''
    
    return sections[0], sections[1]

def parse_headers(raw_headers: str):
    '''
        Function: parse_headers() - parse the raw HTTP headers to a key-value pair table
        Parameters: 
            raw_headers - the raw http headers
        Returns: the parsed http headers in key-value format
    '''
    # Header dictionary
    headers = {}
    lines = raw_headers.splitlines()[1: ]

    for line in lines:
        header = line.split(': ')
        # Add each header title and value to the dictionary
        # If header already exists - 'Set-Cookie' for CSRF and Session ID - Then merge the both
        if (header[0] in headers):
            headers[header[0]] = f"{headers.get(header[0])}\n{header[1]}"
        else:
            headers[header[0]] = header[1]
    
    return headers

def get_response_code(raw_headers):
    '''
        Function: get_response_code() - parse the raw HTTP headers to extract the HTTP status code
        Parameters: 
            raw_headers - the raw http headers
        Returns: the HTTP Response code
    '''
    # Default code: Server Error - try again
    response_code = 500
    if (len(raw_headers) > 0):
        response_code = int(raw_headers.splitlines()[0].split()[1])
    
    return response_code

def get_filename(url_path: str):
    '''
        Function: get_filename() - extracts the filename from the given url path
        Parameters: 
            url_path - the argument url from the script input
        Returns: the filename string to be used to write content to
    '''
    file_name = ''
    split_path = url_path.split('/')

    if (split_path[-1] == '' or split_path[-1].count('.') > 1):
        file_name = 'index.html'
    else:
        file_name = split_path[-1]

    return file_name

def write_to_file(file_name: str, content):
    '''
        Function: write_to_file() - writes and saves content to a file
        Parameters: 
            file_name - the name of the file to write to; if file does not exist, it is created
            content - the content to be written to the file
        Returns: none
    '''
    file = open(file_name, 'wb+')
    file.write(content)
    file.close()

def concat_tcp_flags(tcp_flags: dict):
    '''
        Function: concat_tcp_flags() - concatenates the TCP flags to a single header flag field
        Parameters: 
            tcp_flags - the dictionary (hash table) of TCP flags and their corresponding bit values
        Returns: the concatenated TCP header flag field value
    '''
    return tcp_flags["FLAG_FIN"] + (tcp_flags["FLAG_SYN"] << 1) + (tcp_flags["FLAG_RST"] << 2) + (tcp_flags["FLAG_PSH"] << 3) + (tcp_flags["FLAG_ACK"] << 4) + (tcp_flags["FLAG_URG"] << 5)

def set_syn_bit(tcp_flags: dict):
    '''
        Function: set_syn_bit() - set the SYN flag to 1 in the TCP flags dictionary (hash table) after resetting all flags to 0
        Parameters: 
            tcp_flags - the TCP flags dictionary (hash table)
        Returns: the modified TCP flags
    '''
    tcp_flags = tcp_flags.fromkeys(tcp_flags, 0)
    tcp_flags["FLAG_SYN"] = 1

    return tcp_flags

def set_syn_ack_bits(tcp_flags: dict):
    '''
        Function: set_syn_ack_bits() - set the SYN and ACK flags to 1 in the TCP flags dictionary (hash table) after resetting all flags to 0
        Parameters: 
            tcp_flags - the TCP flags dictionary (hash table)
        Returns: the modified TCP flags
    '''
    tcp_flags = tcp_flags.fromkeys(tcp_flags, 0)
    tcp_flags["FLAG_SYN"] = 1
    tcp_flags["FLAG_ACK"] = 1

    return tcp_flags

def set_ack_bit(tcp_flags: dict):
    '''
        Function: set_ack_bit() - set the ACK flag to 1 in the TCP flags dictionary (hash table) after resetting all flags to 0
        Parameters: 
            tcp_flags - the TCP flags dictionary (hash table)
        Returns: the modified TCP flags
    '''
    tcp_flags = tcp_flags.fromkeys(tcp_flags, 0)
    tcp_flags["FLAG_ACK"] = 1

    return tcp_flags

def set_fin_ack_bits(tcp_flags: dict):
    '''
        Function: set_fin_ack_bits() - set the FIN and ACK flags to 1 in the TCP flags dictionary (hash table) after resetting all flags to 0
        Parameters: 
            tcp_flags - the TCP flags dictionary (hash table)
        Returns: the modified TCP flags
    '''
    tcp_flags = tcp_flags.fromkeys(tcp_flags, 0)
    tcp_flags["FLAG_FIN"] = 1
    tcp_flags["FLAG_ACK"] = 1

    return tcp_flags

def set_fin_bits(tcp_flags: dict):
    '''
        Function: set_fin_bits() - set the FIN flag to 1 in the TCP flags dictionary (hash table) after resetting all flags to 0
        Parameters: 
            tcp_flags - the TCP flags dictionary (hash table)
        Returns: the modified TCP flags
    '''
    tcp_flags = tcp_flags.fromkeys(tcp_flags, 0)
    tcp_flags["FLAG_FIN"] = 1

    return tcp_flags
