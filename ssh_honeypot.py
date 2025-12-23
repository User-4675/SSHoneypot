# Libraries
import logging
from logging.handlers import RotatingFileHandler # Import into files
import socket
import paramiko
import threading
import os

# --- Constants ---
logging_format = logging.Formatter('%(message)s')
HOST_KEY_PATH = ".venv/.ssh_host_rsa_key"
HOST_KEY = ""
SSH_BANNER = "SSH-2.0-OpenSSH_9.1"


# --- Logger & logging Files --- 

# Funnel logger - Capture usernames, passwords and ip addresses
funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
# Credantials Logger - Capture commands run during session
creds_logger = logging.getLogger('CredsLogger')  
creds_logger.setLevel(logging.INFO)



# Initialize and Add handler - Specifies file and formatting
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)



# --- Emulated Shell ---
def emulated_shell(channel, client_ip):
    channel.send(b'$ ') # Simmulate shell
    command = b""
    # response
    
    while True:
        char = channel.recv(1)
        channel.send(char)
        
        if not char:
            channel.close()
        
        command += char
        if char == b'\r':
            inpt = command.strip()
            
            if inpt == b'exit':
                response = b'\nBye!\r\n'
                channel.close()
                return
            elif inpt == b'pwd':
                response = b'\n\\usr\\local\\\r\n'
            elif inpt == b'whoami':
                response = b'\nuser5645\r\n'
            elif inpt == b'ls':
                response = b'\npasswords.txt\r\n'
            elif inpt == b'cat passwords.txt':
                response = b'\nsecret\r\n'
            else:
                response = b'\n' + bytes(inpt) + b'\r\n'
                                
            channel.send(response)
            channel.send(b'$ ')
            command = b""
        

# --- SSH server implementation used by Paramiko ---
class Server(paramiko.ServerInterface):

    # Called when the Server object is created
    # Stores client metadata (not required for SSH itself)
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.input_username = None
        self.input_password = None

    # Called when the client tries to authenticate using a password
    # Returning AUTH_SUCCESSFUL means "accept any username/password"
    def check_auth_password(self, username, password):
        self.input_username = username
        self.input_password = password
        
        funnel_logger.info(
            f"Address={self.client_ip}:{self.client_port} USER={username} PASS={password}"
        )
        
        return paramiko.AUTH_SUCCESSFUL

    # Called when the client requests a new channel
    # SSH supports many channel types; we only allow "session"
    # Returning OPEN_SUCCEEDED allows the channel to be created
    def check_channel_request(self, kind: str, chanid: str) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

        # Reject all other channel types (port forwarding, exec, subsystems)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    # Tells the client which authentication methods are supported
    # In this case, only password authentication is allowed
    def get_allowed_auths(self, username):
        return "password"

    # Called when the client requests an interactive shell
    # Returning True allows the client to start typing commands
    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True  # Accept PTY request


def client_handle(client, addr):
    client_ip = addr[0]
    client_port = addr[1]
    print(f'{client_ip}:{client_port} has connected to server.')
    
    try:
        
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, client_port=client_port)
        
        transport.add_server_key(HOST_KEY)
        transport.start_server(server=server)
        
        channel = transport.accept(100) # Wait 100s to open channel
        if channel is None:
            print("No chanel was opened")
            return

        standard_banner = b'Welcome to Ubuntu 24.04.3 LTS (Noble Numbat) x86_64\r\n\r\n'
        channel.send(standard_banner)
        
        emulated_shell(channel, client_ip)
                
    except Exception as e:
        print(f'Error from {client_ip}: {e}')

    finally:
        try:
            transport.close()
        except Exception as e:
            print(f'Error occured while closing transport: {e}')
        client.close()

# --- Socket Connection ---
def honeypot(address, port):
    
    # Set socket for IPv4 and TCP Connection
    sockfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    
    # This allows the socket to bind to a port that is still marked as in use by the OS, typically due to recently closed connections.
    sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to ip address and port
    sockfd.bind((address, port))
    
    # Set limit for connections
    sockfd.listen(100)
    print(f'SSH server listeing on port {port}...')
    
    while True:
        try:
            # Accept a connection
            client, addr = sockfd.accept()
            
            # Spawn a thread and start it
            ssh_thread = threading.Thread(target=client_handle, args=(client, addr))
            ssh_thread.start()
            
        except Exception as e:
            print(f'{e}')


# Create directories if they don't exist
os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
if not os.path.exists(HOST_KEY_PATH):
    # Generate key and store it
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
else:
    key = paramiko.RSAKey(filename=HOST_KEY_PATH)

HOST_KEY = key
honeypot('127.0.0.1', 2222)