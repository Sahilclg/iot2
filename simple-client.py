import requests
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import time

# Server details - UPDATE THIS
SERVER_IP = "192.168.1.XXX"  # Replace with your Raspberry Pi IP address
SERVER_PORT = 5000
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}"

# Get the public key from server
def get_public_key():
    try:
        print(f"Requesting public key from {SERVER_URL}/public_key")
        response = requests.get(f"{SERVER_URL}/public_key")
        if response.status_code == 200:
            public_key_pem = response.content
            public_key = serialization.load_pem_public_key(public_key_pem)
            print("Successfully retrieved public key")
            return public_key
        else:
            print(f"Error getting public key: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None

# Encrypt data with public key
def encrypt_data(data, public_key):
    data_bytes = data.encode('utf-8')
    encrypted_bytes = public_key.encrypt(
        data_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('ascii')
    return encrypted_b64

# Send test data to server
def send_test_data(public_key):
    test_data = "This is a test message from the client"
    print(f"Encrypting test data: {test_data}")
    
    encrypted_data = encrypt_data(test_data, public_key)
    print(f"Sending encrypted data to {SERVER_URL}/log")
    
    try:
        response = requests.post(
            f"{SERVER_URL}/log",
            json={"data": encrypted_data},
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Server response: {response.status_code} - {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending data: {e}")
        return False

if __name__ == "__main__":
    # Get the public key first
    public_key = get_public_key()
    
    if not public_key:
        print("Failed to get public key from server. Exiting.")
        exit(1)
    
    print("Testing connection to server...")
    success = send_test_data(public_key)
    
    if success:
        print("Test successful! Check the server log file.")
    else:
        print("Test failed. Check the server and network connection.")
