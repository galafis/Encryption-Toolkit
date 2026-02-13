#!/usr/bin/env python3
"""
Encryption Toolkit
Comprehensive encryption and decryption tools for data security.
"""

from flask import Flask, render_template_string, jsonify, request
import base64
import hashlib
from cryptography.fernet import Fernet
import secrets

app = Flask(__name__)

class EncryptionToolkit:
    def __init__(self):
        pass
    
    def generate_key(self):
        """Generate a new encryption key."""
        return Fernet.generate_key()
    
    def encrypt_text(self, text, key):
        """Encrypt text using Fernet symmetric encryption."""
        try:
            f = Fernet(key)
            encrypted = f.encrypt(text.encode())
            return encrypted.decode()
        except Exception as e:
            return None
    
    def decrypt_text(self, encrypted_text, key):
        """Decrypt text using Fernet symmetric encryption."""
        try:
            f = Fernet(key)
            encrypted_bytes = encrypted_text.encode()
            decrypted = f.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            return None
    
    def hash_text(self, text, algorithm='sha256'):
        """Generate hash of text."""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm in algorithms:
            hash_obj = algorithms[algorithm]()
            hash_obj.update(text.encode())
            return hash_obj.hexdigest()
        return None
    
    def generate_password(self, length=12, include_symbols=True):
        """Generate a secure random password."""
        import string
        
        chars = string.ascii_letters + string.digits
        if include_symbols:
            chars += "!@#$%^&*"
        
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def encode_base64(self, text):
        """Encode text to Base64."""
        return base64.b64encode(text.encode()).decode()
    
    def decode_base64(self, encoded_text):
        """Decode Base64 text."""
        try:
            return base64.b64decode(encoded_text.encode()).decode()
        except Exception:
            return None

toolkit = EncryptionToolkit()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Encryption Toolkit</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: white; padding: 30px; border-radius: 15px; text-align: center; margin-bottom: 30px; }
        .tools-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .tool-card { background: white; padding: 25px; border-radius: 15px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .btn { background: #667eea; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn:hover { opacity: 0.9; }
        .output { background: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 15px; font-family: monospace; word-break: break-all; }
        .key-display { background: #e9ecef; padding: 10px; border-radius: 5px; font-family: monospace; font-size: 12px; word-break: break-all; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Encryption Toolkit</h1>
            <p>Comprehensive encryption and decryption tools for data security</p>
        </div>
        
        <div class="tools-grid">
            <!-- Symmetric Encryption -->
            <div class="tool-card">
                <h3>🔒 Symmetric Encryption</h3>
                <div class="form-group">
                    <label>Encryption Key:</label>
                    <div class="key-display" id="encryptionKey">Click "Generate Key" to create a new key</div>
                    <button onclick="generateEncryptionKey()" class="btn">🔑 Generate Key</button>
                </div>
                <div class="form-group">
                    <label>Text to Encrypt:</label>
                    <textarea id="textToEncrypt" rows="3" placeholder="Enter text to encrypt...">Hello, this is a secret message!</textarea>
                </div>
                <button onclick="encryptText()" class="btn">🔒 Encrypt</button>
                <button onclick="decryptText()" class="btn">🔓 Decrypt</button>
                <div id="encryptionOutput" class="output" style="display: none;"></div>
            </div>
            
            <!-- Hashing -->
            <div class="tool-card">
                <h3>🔗 Text Hashing</h3>
                <div class="form-group">
                    <label>Text to Hash:</label>
                    <textarea id="textToHash" rows="3" placeholder="Enter text to hash...">password123</textarea>
                </div>
                <div class="form-group">
                    <label>Hash Algorithm:</label>
                    <select id="hashAlgorithm">
                        <option value="md5">MD5</option>
                        <option value="sha1">SHA-1</option>
                        <option value="sha256" selected>SHA-256</option>
                        <option value="sha512">SHA-512</option>
                    </select>
                </div>
                <button onclick="hashText()" class="btn">🔗 Generate Hash</button>
                <div id="hashOutput" class="output" style="display: none;"></div>
            </div>
            
            <!-- Password Generator -->
            <div class="tool-card">
                <h3>🎲 Password Generator</h3>
                <div class="form-group">
                    <label>Password Length:</label>
                    <input type="number" id="passwordLength" value="12" min="4" max="50">
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="includeSymbols" checked> Include Symbols
                    </label>
                </div>
                <button onclick="generatePassword()" class="btn">🎲 Generate Password</button>
                <div id="passwordOutput" class="output" style="display: none;"></div>
            </div>
            
            <!-- Base64 Encoding -->
            <div class="tool-card">
                <h3>📝 Base64 Encoding</h3>
                <div class="form-group">
                    <label>Text to Encode/Decode:</label>
                    <textarea id="base64Text" rows="3" placeholder="Enter text...">Hello World!</textarea>
                </div>
                <button onclick="encodeBase64()" class="btn">📝 Encode</button>
                <button onclick="decodeBase64()" class="btn">📖 Decode</button>
                <div id="base64Output" class="output" style="display: none;"></div>
            </div>
        </div>
    </div>
    
    <script>
        let currentEncryptionKey = null;
        
        function escapeHtml(str) {
            const div = document.createElement('div');
            div.textContent = str;
            return div.innerHTML;
        }
        
        async function generateEncryptionKey() {
            try {
                const response = await fetch('/api/generate-key', { method: 'POST' });
                const data = await response.json();
                currentEncryptionKey = data.key;
                document.getElementById('encryptionKey').textContent = currentEncryptionKey;
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function encryptText() {
            if (!currentEncryptionKey) {
                alert('Please generate an encryption key first');
                return;
            }
            
            const text = document.getElementById('textToEncrypt').value;
            if (!text) {
                alert('Please enter text to encrypt');
                return;
            }
            
            try {
                const response = await fetch('/api/encrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: text, key: currentEncryptionKey })
                });
                
                const data = await response.json();
                const output = document.getElementById('encryptionOutput');
                output.innerHTML = `<strong>Encrypted:</strong><br>${escapeHtml(data.encrypted)}`;
                output.style.display = 'block';
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function decryptText() {
            if (!currentEncryptionKey) {
                alert('Please generate an encryption key first');
                return;
            }
            
            const encryptedText = document.getElementById('textToEncrypt').value;
            if (!encryptedText) {
                alert('Please enter encrypted text to decrypt');
                return;
            }
            
            try {
                const response = await fetch('/api/decrypt', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ encrypted_text: encryptedText, key: currentEncryptionKey })
                });
                
                const data = await response.json();
                const output = document.getElementById('encryptionOutput');
                if (data.decrypted) {
                    output.innerHTML = `<strong>Decrypted:</strong><br>${escapeHtml(data.decrypted)}`;
                } else {
                    output.textContent = 'Error: Failed to decrypt. Check your key and encrypted text.';
                }
                output.style.display = 'block';
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function hashText() {
            const text = document.getElementById('textToHash').value;
            const algorithm = document.getElementById('hashAlgorithm').value;
            
            if (!text) {
                alert('Please enter text to hash');
                return;
            }
            
            try {
                const response = await fetch('/api/hash', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: text, algorithm: algorithm })
                });
                
                const data = await response.json();
                const output = document.getElementById('hashOutput');
                output.innerHTML = `<strong>${escapeHtml(algorithm.toUpperCase())} Hash:</strong><br>${escapeHtml(data.hash)}`;
                output.style.display = 'block';
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function generatePassword() {
            const length = parseInt(document.getElementById('passwordLength').value);
            const includeSymbols = document.getElementById('includeSymbols').checked;
            
            try {
                const response = await fetch('/api/generate-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ length: length, include_symbols: includeSymbols })
                });
                
                const data = await response.json();
                const output = document.getElementById('passwordOutput');
                output.innerHTML = `<strong>Generated Password:</strong><br>${escapeHtml(data.password)}`;
                output.style.display = 'block';
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function encodeBase64() {
            const text = document.getElementById('base64Text').value;
            
            if (!text) {
                alert('Please enter text to encode');
                return;
            }
            
            try {
                const response = await fetch('/api/base64-encode', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ text: text })
                });
                
                const data = await response.json();
                const output = document.getElementById('base64Output');
                output.innerHTML = `<strong>Base64 Encoded:</strong><br>${escapeHtml(data.encoded)}`;
                output.style.display = 'block';
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        async function decodeBase64() {
            const encodedText = document.getElementById('base64Text').value;
            
            if (!encodedText) {
                alert('Please enter Base64 text to decode');
                return;
            }
            
            try {
                const response = await fetch('/api/base64-decode', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ encoded_text: encodedText })
                });
                
                const data = await response.json();
                const output = document.getElementById('base64Output');
                if (data.decoded) {
                    output.innerHTML = `<strong>Base64 Decoded:</strong><br>${escapeHtml(data.decoded)}`;
                } else {
                    output.textContent = 'Error: Invalid Base64 text';
                }
                output.style.display = 'block';
            } catch (error) {
                console.error('Error:', error);
            }
        }
        
        // Generate initial encryption key
        generateEncryptionKey();
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/generate-key', methods=['POST'])
def generate_key():
    key = toolkit.generate_key()
    return jsonify({'key': key.decode()})

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    text = data.get('text')
    key = data.get('key')
    if not text or not key:
        return jsonify({'error': 'Missing text or key'}), 400
    
    encrypted = toolkit.encrypt_text(text, key.encode())
    return jsonify({'encrypted': encrypted})

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    encrypted_text = data.get('encrypted_text')
    key = data.get('key')
    if not encrypted_text or not key:
        return jsonify({'error': 'Missing encrypted_text or key'}), 400
    
    decrypted = toolkit.decrypt_text(encrypted_text, key.encode())
    return jsonify({'decrypted': decrypted})

@app.route('/api/hash', methods=['POST'])
def hash_text():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    text = data.get('text')
    if not text:
        return jsonify({'error': 'Missing text'}), 400
    algorithm = data.get('algorithm', 'sha256')
    
    hash_result = toolkit.hash_text(text, algorithm)
    return jsonify({'hash': hash_result})

@app.route('/api/generate-password', methods=['POST'])
def generate_password():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    length = data.get('length', 12)
    include_symbols = data.get('include_symbols', True)
    
    password = toolkit.generate_password(length, include_symbols)
    return jsonify({'password': password})

@app.route('/api/base64-encode', methods=['POST'])
def encode_base64():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    text = data.get('text')
    if not text:
        return jsonify({'error': 'Missing text'}), 400
    
    encoded = toolkit.encode_base64(text)
    return jsonify({'encoded': encoded})

@app.route('/api/base64-decode', methods=['POST'])
def decode_base64():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400
    encoded_text = data.get('encoded_text')
    if not encoded_text:
        return jsonify({'error': 'Missing encoded_text'}), 400
    
    decoded = toolkit.decode_base64(encoded_text)
    return jsonify({'decoded': decoded})

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5000)

