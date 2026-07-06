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
    return base64.b64encode(b"Salted__" + salt + ciphertext).decode('utf-8')

# --- Dynamic RSA/AES Hybrid Logic ---
def generate_encrypted_payload(data_dict, rsa_public_key_str):
    json_payload = json.dumps(data_dict, separators=(',', ':'))
    aes_key = os.urandom(32)
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
        headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
        api_session = requests.Session()
        api_session.get("https://wss.sbpdcl.co.in/cportal/", headers=headers)
        
        # 1. Fetch RSA Key
        config_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service", 
            data=encrypt_aes_standard({"action": "getAllWebConfigurations"}, "fgwebcp@2020"), 
            headers={**headers, "Content-Type": "text/plain"}
        )
        rsa_public_key = config_resp.json().get('enc')
        
        # 2. Get NSC Token
        token_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscBridgeService/service", 
            json=generate_encrypted_payload({"action": "getNscToken"}, rsa_public_key), 
            headers=headers
        )
        headers["Authorization"] = f"Bearer {token_resp.json().get('access_token')}"
        
        # 3. Get Bill Details
        details_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service", 
            json=generate_encrypted_payload({"action": "fgexternal/rest/fetchBillDetails/", "req": {"scno": ca_number}, "auth": "TOKEN"}, rsa_public_key), 
            headers=headers
        )
        bill_data = json.loads(details_resp.json()[0]['data'])
        
        # 4. Download PDF
        payload = {
            "action": "billing/getviewbill",
            "method": "POST",
            "req": {
                "billNo": bill_data['billNo'],
                "scno": ca_number,
                "billMonth": bill_data['billMonth'],
                "type": "H"
            },
            "auth": "TOKEN",
            "baseUrlName": ""
        }
        
        pdf_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD", 
            json=generate_encrypted_payload(payload, rsa_public_key), 
            headers=headers
        )
        
        return send_file(io.BytesIO(pdf_resp.content), mimetype='application/pdf', as_attachment=True, download_name=f"Bill_{bill_data['billMonth']}.pdf")
    except Exception as e:
        return {"error": str(e)}, 500