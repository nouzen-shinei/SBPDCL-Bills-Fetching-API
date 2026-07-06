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
    if not ca_number:
        return {"error": "Missing CA number"}, 400
        
    try:
        # Standard headers to perfectly mimic Chrome
        standard_headers = {
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://wss.sbpdcl.co.in",
            "Referer": "https://wss.sbpdcl.co.in/cportal/",
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
        }
        
        api_session = requests.Session()
        
        # 1. Fetch RSA Key (Initializes JSESSIONID)
        config_payload = encrypt_aes_standard({"action": "getAllWebConfigurations"}, "fgwebcp@2020")
        config_resp = api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service",
            data=config_payload,
            headers={"Content-Type": "text/plain", "User-Agent": standard_headers["User-Agent"]}
        )
        rsa_public_key = config_resp.json().get('enc')
        if not rsa_public_key:
            return {"error": "Failed to retrieve RSA Key."}, 500
            
        # 2. Prime 1: Request NSC Token (Triggers Tomcat session bindings)
        try:
            nsc_payload = encrypt_aes_standard({"action": "getNscToken"}, "fgwebcp@2020")
            api_session.post(
                "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscBridgeService/service",
                data=nsc_payload,
                headers={"Content-Type": "text/plain", "User-Agent": standard_headers["User-Agent"]}
            )
        except:
            pass

        # 3. Prime 2: Bill Validation (Binds CA Number to Guest Session)[cite: 5]
        prime_payload_1 = {
            "action": f"billing/getBillValidation/{ca_number}",
            "method": "GET",
            "auth": "NO",
            "baseUrlName": ""
        }
        api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service",
            json=generate_encrypted_payload(prime_payload_1, rsa_public_key),
            headers={**standard_headers, "Content-Type": "application/json"}
        )

        # 4. Prime 3: Fetch Bill Details (Locks context for PDF generation)[cite: 5]
        prime_payload_2 = {
            "action": "fgexternal/rest/fetchBillDetails/",
            "method": "POST",
            "req": {"scno": ca_number},
            "auth": "TOKEN",
            "baseUrlName": "",
            "reqType": "CISENC"
        }
        api_session.post(
            "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service",
            json=generate_encrypted_payload(prime_payload_2, rsa_public_key),
            headers={**standard_headers, "Content-Type": "application/json"}
        )

        # 5. Extract the PDF using Bruteforce Authorization Modes
        now = datetime.now()
        pdf_bytes = b''
        success_m, success_y = "", ""

        for i in range(4):
            m = now.month - i
            y = now.year
            if m <= 0:
                m += 12
                y -= 1
            
            m_str = f"{m:02d}"
            y_str = str(y)
            
            # The backend may demand "TOKEN" or "NO" depending on the load balancer state
            for auth_mode in ["TOKEN", "NO"]:
                raw_payload = {
                    "action": f"billing/getviewbill/{ca_number},{m_str},{y_str},H,PDF,WSS",
                    "method": "GET",
                    "auth": auth_mode, 
                    "baseUrlName": ""
                }
                
                bill_resp = api_session.post(
                    "https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD",
                    json=generate_encrypted_payload(raw_payload, rsa_public_key),
                    headers={**standard_headers, "Content-Type": "application/json"}
                )
                
                # If 200 OK and larger than 1KB, it is the valid binary PDF stream
                if bill_resp.status_code == 200 and len(bill_resp.content) > 1000:
                    pdf_bytes = bill_resp.content
                    success_m = m_str
                    success_y = y_str
                    break
            
            if pdf_bytes:
                break
                
        if not pdf_bytes:
            return {"error": "All 3 priming stages succeeded, but server still refused the PDF generation."}, 404
            
        # 6. Stream directly to Google Apps Script
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'SBPDCL_{success_m}_{success_y}.pdf'
        )
    except Exception as e:
        return {"error": str(e)}, 500