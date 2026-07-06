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
        d_i = hashlib.md5(d_i + password.encode('utf-8') + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt_aes_standard(data_dict, passphrase):
    data_str = json.dumps(data_dict, separators=(',', ':'))
    salt = os.urandom(8)
    key, iv = derive_key_and_iv(passphrase, salt, 32, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data_str.encode('utf-8'), AES.block_size)
    return base64.b64encode(b"Salted__" + salt + cipher.encrypt(padded_data)).decode('utf-8')

# --- Dynamic RSA/AES Hybrid Logic ---
def generate_encrypted_payload(data_dict, rsa_public_key_str):
    json_payload = json.dumps(data_dict, separators=(',', ':'))
    aes_key = os.urandom(16) 
    iv = os.urandom(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(json_payload.encode('utf-8'), AES.block_size)
    encrypted_payload = base64.b64encode(cipher_aes.encrypt(padded_data)).decode('utf-8')
    
    aes_key_hex = binascii.hexlify(aes_key).decode('utf-8')
    clean_key = rsa_public_key_str.replace(' ', '').replace('\n', '').replace('\r', '')
    formatted_key = f"-----BEGIN PUBLIC KEY-----\n{clean_key}\n-----END PUBLIC KEY-----" if "-----BEGIN" not in rsa_public_key_str else rsa_public_key_str
    
    cipher_rsa = PKCS1_v1_5.new(RSA.import_key(formatted_key))
    encrypted_key = base64.b64encode(cipher_rsa.encrypt(aes_key_hex.encode('utf-8'))).decode('utf-8')
    
    return {"encryptedKey": encrypted_key, "payload": encrypted_payload, "iv": binascii.hexlify(iv).decode('utf-8')}

@app.route('/api/get-sbpdcl-bill')
def get_bill():
    ca_number = request.args.get('ca')
    if not ca_number: return {"error": "Missing CA number"}, 400
    
    try:
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://wss.sbpdcl.co.in",
            "Referer": "https://wss.sbpdcl.co.in/cportal/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        api_session = requests.Session()
        
        # 1. RSA (Timeout increased just in case the server is lagging)
        config_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service", 
            data=encrypt_aes_standard({"action": "getAllWebConfigurations"}, "fgwebcp@2020"), 
            headers={**headers, "Content-Type": "text/plain"}, timeout=20
        )
        rsa_public_key = config_resp.json().get('enc')
        
        # 2. NSC Token
        token_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscBridgeService/service", 
            json=generate_encrypted_payload({"action": "getNscToken"}, rsa_public_key), 
            headers={**headers, "Content-Type": "application/json"}, timeout=20
        )
        token = token_resp.json().get('access_token')
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # 3. Extract PDF (We skip the two slow validation APIs and calculate the parameters ourselves)
        now = datetime.now()
        pdf_bytes, success_m, success_y = b'', "", ""

        for i in range(3):
            m, y = now.month - i, now.year
            if m <= 0:
                m += 12; y -= 1
            
            m_str, y_str = f"{m:02d}", str(y)
            
            # The Cheat Code: Generate the exact parameters the server expects
            bill_month_full = f"{m_str}/{y_str}"
            bill_no = f"{y_str}{m_str}{ca_number}"
            
            payload = {
                "action": "billing/getviewbill",
                "method": "POST",
                "req": {
                    "billNo": bill_no,
                    "scno": ca_number,
                    "billMonth": bill_month_full,
                    "type": "H"
                },
                "auth": "TOKEN",
                "baseUrlName": ""
            }
            
            pdf_resp = api_session.post(
                "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD", 
                json=generate_encrypted_payload(payload, rsa_public_key), 
                headers={**headers, "Content-Type": "application/json"}, timeout=25
            )
            
            if pdf_resp.status_code == 200 and len(pdf_resp.content) > 1000:
                pdf_bytes, success_m, success_y = pdf_resp.content, m_str, y_str
                break
                
        if not pdf_bytes:
            return {"error": "Failed to generate PDF byte stream. Bill may not be generated yet."}, 404
            
        return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name=f'SBPDCL_{success_m}_{success_y}.pdf')
        
    except requests.exceptions.ReadTimeout:
        return {"error": "SBPDCL Server timed out. It is currently too slow."}, 504
    except Exception as e:
        return {"error": "Script Exception", "details": str(e)}, 500