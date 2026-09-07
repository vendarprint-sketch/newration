from flask import Flask, jsonify
from flask_cors import CORS
import requests
import base64
import json
import os

# ===== UMANG Encryption (cryptography) =====
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym

app = Flask(__name__)
CORS(app)

# ===================== CONFIG: UMANG Ration Info =====================
GATEWAY = "https://apigw.umangapp.in/onorcApi/ws1/getrationcard"

PUB = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpgmSqIv/3zYAxoNK/6e
LqjeBEHFsiGJCia5wdQuhCw54ceg6EyKc5mPrkEnK7CYgbJxSQO37HbnWIROMN6k
RQqxa1kZFFS+xQPZ9z4Gs+njypX8HNKcse2/kbwbIX4y8kcCENVVOV8URK8+znEs
uN/UCzJXv2Pg0KII5ofb8wAvYNXkZ44DhcWnyxO6JohbuMvpt096NBkdq8lWtRra
ppL3HqpTG4Fd5H4v9b7fD8rAhBB8cAbiM2nyBz51VDovS/SZheIemKjwGLGMDiMe
NcQGryOTZASX+jxe69NoFR9bQ8+5jN/88x5k53UzV8en+HRKbYjgUJzZOVfu3fL/
WQIDAQAB
-----END PUBLIC KEY-----"""

PRIV = b"""-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCumCZKoi//fNgD
Gg0r/p4uqN4EQcWyIYkKJrnB1C6ELDnhx6DoTIpzmY+uQScrsJiBsnFJA7fsdudY
hE4w3qRFCrFrWRkUVL7FA9n3Pgaz6ePKlfwc0pyx7b+RvBshfjLyRwIQ1VU5XxRE
rz7OcSy439QLMle/Y+DQogjmh9vzAC9g1eRnjgOFxafLE7omiFu4y+m3T3o0GR2r
yVa1GtqmkvceqlMbgV3kfi/1vt8PysCEEHxwBuIzafIHPnVUOi9L9JmF4h6YqPAY
sYwOIx41xAavI5NkBJf6PF7r02gVH1tDz7mM3/zzHmTndTNXx6f4dEptiOBQnNk5
V+7d8v9ZAgMBAAECggEActY8iWZ4L5GL+y5Nb5x/qq0DqsUgJXQNURH7qFPJbMIy
KCFH4sNFZZehe7n666+x/8zA2oeJmAz1SbFsRJSMc6T+4V6vMkIzYB6SZR71Ba1X
WM6iDsswqY95K4AQUE1TcSvnXe8TqTKygCLMKrkh80+1hs/MC2TEYDXTqN2/e+qO
Bq6/RQ4A7E+Qd1R6/mFEHZJfmvMVl0lBmowHk060/JAgeSxE5VPnP2pQXad21w/n
BtSoQDOKpAzbcSIgn4vLavtUlS87XYQ8bq3Mc4sPQe9RZ9o89aQrau0SmdgNeGYV
i0tWhP2lm3b8C3XcgDQi6LwnZpzwCo9m5fEcJM4IyQKBgQD//t26TkBC2h4trvbO
ID2SN2hPiBySxjb3Eoaiy58ryF/d4Im56Xf61ksuy0od52vgNzW03As6vPjTJpqy
/EeJrOZHLdZSOiFZzqcgXUcir2O6gM/WIU/0x/Ge7nnp0DfwTYgTNzpJA+csR9aD
FhOu9e+xogJ0lV4eCEBjjC+Q+wKBgQCumOxDZkaH9uuXSbrGTsrEMO0439oLM+Er
6L+Pdpy8qY0Q5ZYp2C1ZZBz8DwH6NwwKY/JcvrVVS5D90mmqsm39ubeIrmv7C04T
WBQqYRp9dgRkUkVo9BGM6EqA2q/D2JT/sr/72h5FEsMblHSVEXbCo/QLYvCglxSs
7jhx5tDIuwKBgQC/W2epJWc50cvvQDNzP3xm+Q37LXaWbJ6Xr/x+YpFX7A9lTrwF
AbVTBq7qisGbeusTjpGR4U5vmOSzCc9n7dcX3evA102254cYl7YsJi3PiqWUu0cg
/IPFKVS/BeqR0biO45XNL2JdRBKg8g4yrOUHywVilgUZ2rGg53AiOZ8w0wKBgQCp
by/AjI0fvwiLrXo6nhX55H0hd2LTAkqe4OSdJX8fOu7xmctq2iXQHO5f0XSazDa8
EpgNVukEWCvhlgMDKtrAoiyw0ItreWIQNaaEJe2eGRxT+t7u5gPuGTLL7u0pApI9
vcq/bsF3SKjcp+mnC+aTJqZbMm3Pei4PT7KpHlQ4pwKBgDeLXCwO6cCa+4nV4t5k
tCEzQPiu/yEMAL0hf3RwPr7WuckwyHm3cUt7DFCEf6+bJj+hpxVXGcdgVxDZjyh4
s8YE8AAd+2iv8I61gF475KAOOMbkt21TzTI0y2R2BN3JvB1iTmf6CkV6C82b4UEL
lKjEOX342756ZWQbhB8Yld1T
-----END PRIVATE KEY-----"""

_pub = serialization.load_pem_public_key(PUB)
_priv = serialization.load_pem_private_key(PRIV, password=None)
_oaep = asym.OAEP(mgf=asym.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

SESSION = {
    "tkn": "mk27c18eec-0c0d-4b14-aff1-1b2bf90e4642/2", "trkr": "213132", "lang": "en",
    "lat": "21", "lon": "90", "lac": "90", "usag": "90", "apitrkr": "123234",
    "usrid": "4088903933", "mode": "web", "pltfrm": "linux", "did": "123234",
    "deptid": "317", "formtrkr": "0", "srvid": "1519", "subsid": "0", "subsid2": "0",
    "sessionId": "571998755919145", "userName": "umang", "idType": "R", "token": "Um@93259@"
}

UMANG_HEADERS = {
    "User-Agent": "Mozilla/5.0", "Accept": "application/json", "Content-Type": "application/json",
    "subsid": "0", "subsid2": "0", "deptid": "317", "tenantid": "", "formtrkr": "0",
    "x-api-key": "VKE9PnbY5k1ZYapR5PyYQ33I26sXTX569Ed7eqyg", "srvid": "1519"
}

def umang_encrypt(plaintext: str) -> str:
    aes_key, iv = os.urandom(32), os.urandom(16)
    padder = sym.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    ek, eiv = _pub.encrypt(aes_key, _oaep), _pub.encrypt(iv, _oaep)
    return ":".join(base64.b64encode(x).decode() for x in (ek, eiv, ct))

def umang_decrypt(blob: str) -> str:
    parts = blob.strip().split(":")
    if len(parts) == 3:
        aes_key = _priv.decrypt(base64.b64decode(parts[0]), _oaep)
        iv = _priv.decrypt(base64.b64decode(parts[1]), _oaep)
        ct = base64.b64decode(parts[2])
    elif len(parts) == 2:
        aes_key = _priv.decrypt(base64.b64decode(parts[0]), _oaep)
        ct = base64.b64decode(parts[1])
        iv, ct = ct[:16], ct[16:]
    
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    raw = decryptor.update(ct) + decryptor.finalize()
    unpadder = sym.PKCS7(128).unpadder()
    return (unpadder.update(raw) + unpadder.finalize()).decode("utf-8")

def get_umang_ration_info(ration_number: str) -> dict:
    body = dict(SESSION)
    body["id"] = ration_number
    payload = umang_encrypt(json.dumps(body, separators=(",", ":")))
    r = requests.post(GATEWAY, data=payload, headers=UMANG_HEADERS, timeout=20)
    try: return json.loads(r.text)
    except: return json.loads(umang_decrypt(r.text))

# ===================== FLASK ROUTES =====================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "ok": True,
        "routes": {
            "/ration/<ration_number>": "Fetch Ration Card details"
        }
    })

@app.route("/ration/<number>", methods=["GET"])
def ration_info(number):
    try:
        return jsonify(get_umang_ration_info(number))
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
