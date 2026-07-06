from flask import Flask, request, send_file
from datetime import datetime
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
    data_str = json.dumps(data_dict, separators=(',', ':'))
    salt = os.urandom(8)
    key, iv = derive_key_and_iv(passphrase.encode('utf-8'), salt, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_str.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    final_bytes = b"Salted__" + salt + ciphertext
    return base64.b64encode(final_bytes).decode('utf-8')

# --- Dynamic RSA/AES Hybrid Logic ---
def generate_encrypted_payload(data_dict, rsa_public_key_str):
    json_payload = json.dumps(data_dict, separators=(',', ':'))
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(json_payload.encode('utf-8'), AES.block_size)
    encrypted_payload = base64.b64encode(cipher_aes.encrypt(padded_data)).decode('utf-8')
    
    aes_key_hex = binascii.hexlify(aes_key).decode('utf-8')
    
    if "-----BEGIN PUBLIC KEY-----" not in rsa_public_key_str:
        clean_key = rsa_public_key_str.replace(' ', '').replace('\n', '').replace('\r', '')
        formatted_key = f"-----BEGIN PUBLIC KEY-----\n{clean_key}\n-----END PUBLIC KEY-----"
    else:
        formatted_key = rsa_public_key_str
        
    rsa_key = RSA.import_key(formatted_key)
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
        # 1. Fetch the live RSA Public Key
        raw_config_dict = {"action": "getAllWebConfigurations"}
        config_payload = encrypt_aes_standard(raw_config_dict, "fgwebcp@2020")
        
        config_resp = requests.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service",
            data=config_payload,
            headers={"Content-Type": "text/plain"}
        )
        
        config_data = config_resp.json()
        if 'enc' not in config_data:
            return {"error": f"Failed to retrieve RSA Key. Server responded with: {config_resp.text}"}, 500
            
        rsa_public_key = config_data['enc'] 
        
        # 2. Smart Loop: Generate formats for the last 6 months
        now = datetime.now()
        candidates = []
        
        for i in range(6):
            m = now.month - i
            y = now.year
            if m <= 0:
                m += 12
                y -= 1
            
            m_dt = datetime(y, m, 1)
            # Prioritize string format (JUL), then digit format (07)
            candidates.append((m_dt.strftime("%b").upper(), str(y)))
            candidates.append((f"{m:02d}", str(y)))
        
        headers = {
            "Content-Type": "application/json",
            "Referer": "https://wss.sbpdcl.co.in/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        pdf_bytes = b''
        successful_month = ""
        successful_year = ""

        # 3. Fire requests backwards until we catch a valid PDF
        for m_str, y_str in candidates:
            raw_payload = {
                "action": f"billing/getviewbill/{ca_number},{m_str},{y_str},0,PDF,WSS",
                "method": "GET",
                "auth": "TOKEN",
                "baseUrlName": ""
            }
            encrypted_data = generate_encrypted_payload(raw_payload, rsa_public_key)
            
            bill_resp = requests.post(
                "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD",
                json=encrypted_data,
                headers=headers
            )
            
            # Check if it is a 200 OK and larger than 1KB (meaning it is a real PDF)
            if bill_resp.status_code == 200 and len(bill_resp.content) > 1000:
                pdf_bytes = bill_resp.content
                successful_month = m_str
                successful_year = y_str
                break
                
        if not pdf_bytes:
            return {"error": "Tried all formats for the last 6 months, but the server returned 0 bytes. Check if a bill is generated."}, 404
            
        # 4. Return the valid PDF bytes directly to Apps Script
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'SBPDCL_{successful_month}_{successful_year}.pdf'
        )
    except Exception as e:
        return {"error": str(e)}, 500