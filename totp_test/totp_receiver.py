import socket
import pyotp
import time
HOST = "127.0.0.1"
PORT = 5000
SECRET = "JBSWY3DPEHPK3PXP"
ALLOWED_IPS = ["127.0.0.1"]  
totp = pyotp.TOTP(SECRET)
used_timestamps = set()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)
print("Ground control listening...")

while True:
    conn, addr = server.accept()
    client_ip = addr[0]

  
    if client_ip not in ALLOWED_IPS:
        print("Rejected: unauthorized IP", client_ip)
        conn.close()
        continue

    data = conn.recv(1024).decode()
    conn.close()

    try:
        command, timestamp_str, received_otp = data.split("|")
        timestamp = int(timestamp_str)

       
        if timestamp in used_timestamps:
            print("Rejected: replay attack detected")
            continue

      
        current_time = int(time.time())
        if abs(current_time - timestamp) > 10:
            print("Rejected: expired packet")
            continue

 
        if totp.verify(received_otp, valid_window=1):
            used_timestamps.add(timestamp)
            print("Accepted command:", command)
        else:
            print("Rejected: invalid OTP")

    except Exception as e:
        print("Malformed packet:", e)
