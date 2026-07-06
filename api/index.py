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
    if not ca_number: return {"error": "Missing CA number"}, 400
    
    try:
        standard_headers = {
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://wss.sbpdcl.co.in",
            "Referer": "https://wss.sbpdcl.co.in/cportal/",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
        }
        
        api_session = requests.Session()
        api_session.get("https://wss.sbpdcl.co.in/cportal/", headers=standard_headers)
        
        # 1. RSA
        config_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service", 
            data=encrypt_aes_standard({"action": "getAllWebConfigurations"}, "fgwebcp@2020"), 
            headers={**standard_headers, "Content-Type": "text/plain"}
        )
        rsa_public_key = config_resp.json().get('enc')
            
        # 2. NSC Token
        nsc_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscBridgeService/service", 
            json=generate_encrypted_payload({"action": "getNscToken"}, rsa_public_key), 
            headers={**standard_headers, "Content-Type": "application/json"}
        )
        
        # --- CRITICAL FIX: Inject the Bearer Token into all future headers[cite: 5] ---
        access_token = nsc_resp.json().get('access_token')
        if access_token:
            standard_headers["Authorization"] = f"Bearer {access_token}"
            
        json_headers = {**standard_headers, "Content-Type": "application/json"}
        
        # 3. Bill Validation[cite: 5]
        api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service", 
            json=generate_encrypted_payload({"action": f"billing/getBillValidation/{ca_number}", "method": "GET", "auth": "NO", "baseUrlName": ""}, rsa_public_key), 
            headers=json_headers
        )

        # 4. Fetch Details[cite: 5]
        det_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service", 
            json=generate_encrypted_payload({"action": "fgexternal/rest/fetchBillDetails/", "method": "POST", "req": {"scno": ca_number}, "auth": "TOKEN", "baseUrlName": "", "reqType": "CISENC"}, rsa_public_key), 
            headers=json_headers
        )

        # --- NEW: Dynamically parse the exact bill month and year from the response ---
        candidates = []
        try:
            det_data = det_resp.json()
            inner_json = json.loads(det_data[0]['data'])
            b_month = inner_json.get('billMonth')
            b_year = inner_json.get('billYear')
            if b_month and b_year:
                candidates.append((str(b_month).zfill(2), str(b_year)))
        except:
            pass

        # Fallback loop just in case
        now = datetime.now()
        pdf_bytes, success_m, success_y = b'', "", ""

        for i in range(4):
            m, y = now.month - i, now.year
            if m <= 0:
                m += 12; y -= 1
            m_str, y_str = f"{m:02d}", str(y)
            if (m_str, y_str) not in candidates:
                candidates.append((m_str, y_str))

        # 5. Extract PDF[cite: 5]
        for m_str, y_str in candidates:
            for lang in ['H', 'E']:
                bill_resp = api_session.post(
                    "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD", 
                    json=generate_encrypted_payload({"action": f"billing/getviewbill/{ca_number},{m_str},{y_str},{lang},PDF,WSS", "method": "GET", "auth": "TOKEN", "baseUrlName": ""}, rsa_public_key), 
                    headers=json_headers
                )
                
                if bill_resp.status_code == 200 and len(bill_resp.content) > 1000:
                    pdf_bytes, success_m, success_y = bill_resp.content, m_str, y_str
                    break
            if pdf_bytes: break
                
        if not pdf_bytes:
            return {"error": "Server returned 0 bytes.", "candidates": candidates}, 404
            
        return send_file(io.BytesIO(pdf_bytes), mimetype='application/pdf', as_attachment=True, download_name=f'SBPDCL_{success_m}_{success_y}.pdf')
    except Exception as e:
        return {"error": str(e)}, 500