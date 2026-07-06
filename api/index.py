from flask import Flask, request, jsonify
import json
import base64
import binascii
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

app = Flask(__name__)

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = hashlib.md5(d_i + password.encode('utf-8') + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

@app.route('/api/crypto', methods=['POST'])
def crypto():
    try:
        req = request.json
        crypto_type = req.get('type')
        
        # 1. Encrypt static strings (like the RSA Config request)
        if crypto_type == 'static':
            data_str = json.dumps(req.get('data'), separators=(',', ':'))
            salt = os.urandom(8)
            key, iv = derive_key_and_iv("fgwebcp@2020", salt, 32, 16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = pad(data_str.encode('utf-8'), AES.block_size)
            enc_str = base64.b64encode(b"Salted__" + salt + cipher.encrypt(padded)).decode('utf-8')
            return jsonify({"result": enc_str})
            
        # 2. Encrypt dynamic JSON payloads with the RSA Key
        elif crypto_type == 'dynamic':
            json_payload = json.dumps(req.get('data'), separators=(',', ':'))
            rsa_public_key_str = req.get('rsa_key')
            
            aes_key = os.urandom(32) 
            iv = os.urandom(16)
            cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
            padded = pad(json_payload.encode('utf-8'), AES.block_size)
            enc_payload = base64.b64encode(cipher_aes.encrypt(padded)).decode('utf-8')
            
            aes_key_hex = binascii.hexlify(aes_key).decode('utf-8')
            clean_key = rsa_public_key_str.replace(' ', '').replace('\n', '').replace('\r', '')
            formatted_key = f"-----BEGIN PUBLIC KEY-----\n{clean_key}\n-----END PUBLIC KEY-----" if "-----BEGIN" not in rsa_public_key_str else rsa_public_key_str
            
            cipher_rsa = PKCS1_v1_5.new(RSA.import_key(formatted_key))
            enc_key = base64.b64encode(cipher_rsa.encrypt(aes_key_hex.encode('utf-8'))).decode('utf-8')
            
            return jsonify({
                "encryptedKey": enc_key, 
                "payload": enc_payload, 
                "iv": binascii.hexlify(iv).decode('utf-8')
            })
            
        return jsonify({"error": "Invalid crypto type"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500