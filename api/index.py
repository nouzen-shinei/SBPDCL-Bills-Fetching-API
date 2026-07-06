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
        # Create a persistent session to maintain the JSESSIONID cookie across requests[cite: 3]
        api_session = requests.Session()
        
        # 1. Fetch the live RSA Public Key using static fallback encryption[cite: 3]
        raw_config_dict = {"action": "getAllWebConfigurations"}
        config_payload = encrypt_aes_standard(raw_config_dict, "fgwebcp@2020")
        
        config_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service",
            data=config_payload,
            headers={"Content-Type": "text/plain"}
        )
        
        config_data = config_resp.json()
        if 'enc' not in config_data:
            return {"error": "Failed to retrieve RSA Key."}, 500
            
        rsa_public_key = config_data['enc'] 
        
        # 2. PRIMING THE SESSION (The Missing Step)
        # We must call the search endpoint first so the server binds our CA details to the session cookies[cite: 1]
        prime_payload = {
            "action": "fgexternal/rest/fetchBillDetails/",
            "method": "POST",
            "req": {"scno": ca_number},
            "auth": "TOKEN",
            "baseUrlName": "",
            "reqType": "CISENC"
        }
        encrypted_prime_data = generate_encrypted_payload(raw_payload=prime_payload, rsa_public_key_str=rsa_public_key)
        
        api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.PublishData/service",
            json=encrypted_data_prime,
            headers={"Content-Type": "application/json"}
        )

        # 3. Generate date configurations for the smart fallback loop
        now = datetime.now()
        candidates = []
        for i in range(3):
            m = now.month - i
            y = now.year
            if m <= 0:
                m += 12
                y -= 1
            candidates.append((f"{m:02d}", str(y)))
        
        headers = {
            "Content-Type": "application/json",
            "Referer": "https://wss.sbpdcl.co.in/cportal/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        pdf_bytes = b''
        success_m, success_y = "", ""

        # 4. Request the bill PDF inside the authenticated session container[cite: 3]
        for m_str, y_str in candidates:
            # Reverting auth back to "TOKEN" to match the main app configuration exactly[cite: 1]
            raw_payload = {
                "action": f"billing/getviewbill/{ca_number},{m_str},{y_str},H,PDF,WSS",
                "method": "GET",
                "auth": "TOKEN", 
                "baseUrlName": ""
            }
            
            encrypted_data = generate_encrypted_payload(raw_payload, rsa_public_key)
            
            bill_resp = api_session.post(
                "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD",
                json=encrypted_data,
                headers=headers
            )
            
            if bill_resp.status_code == 200 and len(bill_resp.content) > 1000:
                pdf_bytes = bill_resp.content
                success_m = m_str
                success_y = y_str
                break
                
        if not pdf_bytes:
            return {"error": "Session primed but server returned 0 bytes for all recent months. The bill may not be issued yet."}, 404
            
        # 5. Return the valid binary file directly to Google Apps Script[cite: 3]
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'SBPDCL_{success_m}_{success_y}.pdf'
        )
    except Exception as e:
        return {"error": str(e)}, 500