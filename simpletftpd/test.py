import socket

# Define the server's IP address and port
SERVER_IP = '0.0.0.0'  # Listen on all available network interfaces
SERVER_PORT = 12345   # Choose a port number

# Create a UDP socket
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the server address and port
udp_socket.bind((SERVER_IP, SERVER_PORT))

print(f"UDP server is listening on {SERVER_IP}:{SERVER_PORT}")

while True:
    # Receive data from a client
    data, client_address = udp_socket.recvfrom(1024)  # Maximum buffer size is 1024 bytes
    print(f"Received data from {client_address}: {data.decode('utf-8')}")

    # You can add your processing logic here if needed

# Close the socket when done (This part will never be reached in this example)
udp_socket.close()
