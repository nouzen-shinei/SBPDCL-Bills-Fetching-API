from flask import Flask, request, send_file
import requests
import json
import base64
import binascii
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

app = Flask(__name__)

# --- Simplified Helpers ---
def encrypt_aes_standard(data, password):
    data_str = json.dumps(data, separators=(',', ':'))
    salt = os.urandom(8)
    # Using the standard Fluentgrid key derivation
    d = b''
    d_i = b''
    while len(d) < 48:
        d_i = hashlib.md5(d_i + password.encode('utf-8') + salt).digest()
        d += d_i
    key, iv = d[:32], d[32:48]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(b"Salted__" + salt + cipher.encrypt(pad(data_str.encode(), AES.block_size))).decode('utf-8')

def generate_encrypted_payload(data, rsa_key_str):
    json_str = json.dumps(data, separators=(',', ':'))
    aes_key, iv = os.urandom(32), os.urandom(16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    payload = base64.b64encode(cipher_aes.encrypt(pad(json_str.encode(), AES.block_size))).decode('utf-8')
    
    clean_key = rsa_key_str.replace(' ', '').replace('\n', '').replace('\r', '')
    rsa_key = RSA.import_key(f"-----BEGIN PUBLIC KEY-----\n{clean_key}\n-----END PUBLIC KEY-----")
    encrypted_key = base64.b64encode(PKCS1_v1_5.new(rsa_key).encrypt(binascii.hexlify(aes_key))).decode('utf-8')
    
    return {"encryptedKey": encrypted_key, "payload": payload, "iv": binascii.hexlify(iv).decode('utf-8')}

@app.route('/api/get-sbpdcl-bill')
def get_bill():
    ca_number = request.args.get('ca')
    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"})
        
        # 1. Prime the load balancer
        session.get("https://wss.sbpdcl.co.in/cportal/")
        
        # 2. RSA Key
        key_resp = session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service", 
                               data=encrypt_aes_standard({"action": "getAllWebConfigurations"}, "fgwebcp@2020"),
                               headers={"Content-Type": "text/plain"})
        rsa_key = key_resp.json().get('enc')
        
        # 3. Get Auth Token
        token_resp = session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscBridgeService/service",
                                 json=generate_encrypted_payload({"action": "getNscToken"}, rsa_key))
        token = token_resp.json().get('access_token')
        
        # 4. Fetch Bill Details (The key data loader)
        details = session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service",
                              json=generate_encrypted_payload({"action": "fgexternal/rest/fetchBillDetails/", "req": {"scno": ca_number}, "auth": "TOKEN"}, rsa_key),
                              headers={"Authorization": f"Bearer {token}"})
        
        bill_info = json.loads(details.json()[0]['data'])
        
        # 5. DOWNLOAD PDF (Using the exact schema found in your logs)
        download_payload = {
            "action": "DOWNLOAD",
            "accno": ca_number,
            "billNo": bill_info['billNo'],
            "billMonth": bill_info['billMonth'],
            "billType": "B"
        }
        
        final_resp = session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD",
                                 json=generate_encrypted_payload(download_payload, rsa_key),
                                 headers={"Authorization": f"Bearer {token}"})
        
        if final_resp.status_code == 200 and len(final_resp.content) > 1000:
            return send_file(io.BytesIO(final_resp.content), mimetype='application/pdf')
            
        return {"error": "Server failed to return PDF", "status": final_resp.status_code}, 500
    except Exception as e:
        return {"error": str(e)}, 500