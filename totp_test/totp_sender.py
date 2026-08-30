import socket
import pyotp
import time
HOST = "127.0.0.1"
PORT = 5000
SECRET = "JBSWY3DPEHPK3PXP"
totp = pyotp.TOTP(SECRET)
command = "MOVE_FORWARD"
timestamp = int(time.time())
otp = totp.now()
message = f"{command}|{timestamp}|{otp}"
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.send(message.encode())
sock.close()
print("Sent:", message)
