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

# [Keep your existing derive_key_and_iv, encrypt_aes_standard, and generate_encrypted_payload functions exactly as they are]

@app.route('/api/get-sbpdcl-bill')
def get_bill():
    ca_number = request.args.get('ca')
    try:
        api_session = requests.Session()
        headers = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
        
        # 1. Get RSA Key
        rsa_resp = api_session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.CPCommonConfigService/service", 
                                   data=encrypt_aes_standard({"action": "getAllWebConfigurations"}, "fgwebcp@2020"), 
                                   headers={"Content-Type": "text/plain", "User-Agent": "Mozilla/5.0"})
        rsa_key = rsa_resp.json().get('enc')
        
        # 2. Get NSC Token
        token_resp = api_session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscBridgeService/service", 
                                     json=generate_encrypted_payload({"action": "getNscToken"}, rsa_key), headers=headers)
        token = token_resp.json().get('access_token')
        headers["Authorization"] = f"Bearer {token}"
        
        # 3. Get Bill Details (This provides the 'billNo' and 'billMonth' dynamically)
        details_resp = api_session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.SpmIntegrationsData/service", 
                                       json=generate_encrypted_payload({"action": "fgexternal/rest/fetchBillDetails/", "req": {"scno": ca_number}, "auth": "TOKEN"}, rsa_key), 
                                       headers=headers)
        
        bill_data = json.loads(details_resp.json()[0]['data'])
        
        # 4. Download PDF using the exact structure captured from your debugger
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
        
        pdf_resp = api_session.post("https://wss.sbpdcl.co.in/fgweb/web/json/plugin/com.fluentgrid.cp.api.NscUploadBridgeService/service?&rtype=DOWNLOAD", 
                                    json=generate_encrypted_payload(payload, rsa_key), headers=headers)
        
        return send_file(io.BytesIO(pdf_resp.content), mimetype='application/pdf', as_attachment=True, download_name=f"Bill_{bill_data['billMonth']}.pdf")
    except Exception as e:
        return {"error": str(e)}, 500