import socket
import subprocess

# little control program to remotly reset libreswan connections, as it is actually impossible to always be able to do this via the protocols
libre = "sudo ipsec auto --down vm1tovm2"
swan = "sudo ipsec down vm1tovm2"

restart = "sudo ipsec restart"

# Define host and port number
HOST = ''
PORT = 20003 
 

# Create a datagram socket

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip

UDPServerSocket.bind((HOST, PORT))

print(f"UDP server up and listening on {PORT}")

# Listen for incoming datagrams
UDPServerSocket.recv(0)
while(True):

    message, client_address = UDPServerSocket.recvfrom(1024)

    print(f"Received message from {client_address}: {message.decode()}")
    
    # kill connections
    if message.decode() == "RESET":
        try:
            print("Resetting...")
            output = subprocess.run(libre, shell=True, timeout=5)
            output = subprocess.run(swan, shell=True, timeout=5)
            print("Done")
        except Exception as e:
            print(e)

    elif message.decode() == "KILL":
        try:
            print("Restarting...")
            output = subprocess.run(restart, shell=True)
        except Exception as e:
            print(e)
    