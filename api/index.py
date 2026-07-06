from flask import Flask, request, send_file
import requests
import io
import json
import base64
import binascii
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

app = Flask(__name__)

# --- CryptoJS Standard AES Fallback Logic ---
def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt_aes_standard(data_dict, passphrase):
    data_str = json.dumps(data_dict)
    salt = os.urandom(8)
    key, iv = derive_key_and_iv(passphrase.encode('utf-8'), salt, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_str.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # CryptoJS standard format: "Salted__" + salt + ciphertext
    final_bytes = b"Salted__" + salt + ciphertext
    return base64.b64encode(final_bytes).decode('utf-8')

# --- Dynamic RSA/AES Hybrid Logic ---
def generate_encrypted_payload(data_dict, rsa_public_key_pem):
    json_payload = json.dumps(data_dict)
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(json_payload.encode('utf-8'), AES.block_size)
    encrypted_payload = base64.b64encode(cipher_aes.encrypt(padded_data)).decode('utf-8')
    
    aes_key_hex = binascii.hexlify(aes_key).decode('utf-8')
    rsa_key = RSA.import_key(rsa_public_key_pem)
    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    encrypted_key = base64.b64encode(cipher_rsa.encrypt(aes_key_hex.encode('utf-8'))).decode('utf-8')
    
    return {
        "encryptedKey": encrypted_key,
        "payload": encrypted_payload,
        "iv": binascii.hexlify(iv).decode('utf-8')
    }

@app.route('/api/get-sbpdcl-bill')
def get_bill():
    ca_number = request.args.get('ca')
    if not ca_number:
        return {"error": "Missing CA number"}, 400
        
    try:
        # 1. Fetch the live RSA Public Key using the static fallback encryption
        config_payload = encrypt_aes_standard({"action": "getAllWebConfigurations"}, "fgwebcp@2020")
        
        config_resp = requests.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service",
            json=config_payload,
            headers={"Content-Type": "application/json"}
        )
        config_data = config_resp.json()
        
        if 'enc' not in config_data:
            return {"error": f"Failed to retrieve RSA Key. Server responded with: {config_resp.text}"}, 500
            
        rsa_public_key = config_data['enc'] 
        
        # 2. Generate the dynamic encrypted payload for the bill request
        raw_payload = {"strCANumber": ca_number}
        encrypted_data = generate_encrypted_payload(raw_payload, rsa_public_key)
        
        # 3. Request the actual bill PDF
        bill_resp = requests.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD",
            json=encrypted_data,
            headers={"Content-Type": "application/json"}
        )
        
        if bill_resp.status_code != 200:
            return {"error": f"Failed to download bill. Status: {bill_resp.status_code}"}, 500
            
        # 4. Return the PDF bytes directly to Apps Script
        return send_file(
            io.BytesIO(bill_resp.content),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'SBPDCL_{ca_number}.pdf'
        )
    except Exception as e:
        return {"error": str(e)}, 500