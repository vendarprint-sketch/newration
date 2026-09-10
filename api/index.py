from flask import Flask, jsonify, request
import requests, base64, secrets, json, time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import os

app = Flask(__name__)

PRIVATE_KEY = """-----BEGIN PRIVATE KEY-----
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

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArpgmSqIv/3zYAxoNK/6e
LqjeBEHFsiGJCia5wdQuhCw54ceg6EyKc5mPrkEnK7CYgbJxSQO37HbnWIROMN6k
RQqxa1kZFFS+xQPZ9z4Gs+njypX8HNKcse2/kbwbIX4y8kcCENVVOV8URK8+znEs
uN/UCzJXv2Pg0KII5ofb8wAvYNXkZ44DhcWnyxO6JohbuMvpt096NBkdq8lWtRra
ppL3HqpTG4Fd5H4v9b7fD8rAhBB8cAbiM2nyBz51VDovS/SZheIemKjwGLGMDiMe
NcQGryOTZASX+jxe69NoFR9bQ8+5jN/88x5k53UzV8en+HRKbYjgUJzZOVfu3fL/
WQIDAQAB
-----END PUBLIC KEY-----"""

UMANG_TKN = "mnf4758232-9b59-4dd4-bb68-f2d8c1cbef70/1"
UMANG_UID = "4088903933"
API_KEY   = "VKE9PnbY5k1ZYapR5PyYQ33I26sXTX569Ed7eqyg"

# ==================== CRYPTO ====================
def encrypt(data: dict) -> str:
    pub = RSA.import_key(PUBLIC_KEY)
    key = secrets.token_bytes(32)
    iv  = secrets.token_bytes(16)
    ct  = AES.new(key, AES.MODE_CBC, iv).encrypt(
              pad(json.dumps(data, separators=(',',':')).encode(), 16))
    rsa = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    return (base64.b64encode(rsa.encrypt(key)).decode() + ":" +
            base64.b64encode(rsa.encrypt(iv)).decode()  + ":" +
            base64.b64encode(ct).decode())

def decrypt(body: str) -> dict:
    parts = body.strip().split(":")
    priv  = RSA.import_key(PRIVATE_KEY)
    rsa   = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    key   = rsa.decrypt(base64.b64decode(parts[0]))
    iv    = rsa.decrypt(base64.b64decode(parts[1]))
    ct    = base64.b64decode(parts[2])
    pt    = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    return json.loads(pt.decode())

# ==================== ONORC HEADERS ====================
def get_onorc_headers():
    return {
        "x-api-key": API_KEY,
        "content-type": "application/json",
        "accept": "application/json",
        "deptid": "317",
        "srvid": "1519",
        "subsid": "0",
        "subsid2": "0",
        "formtrkr": "0",
        "tenantid": "",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
        "origin": "https://web.umang.gov.in",
        "referer": "https://web.umang.gov.in/",
        "accept-language": "en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,hi;q=0.6",
        "sec-ch-ua": '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "sec-fetch-site": "cross-site",
        "sec-fetch-mode": "cors",
        "sec-fetch-dest": "empty",
    }

def onorc_base_body():
    ts = int(time.time() * 1000)
    return {
        "tkn":      UMANG_TKN,
        "trkr":     str(ts),
        "lang":     "en",
        "lat":      "21",
        "lon":      "90",
        "lac":      "90",
        "usag":     "90",
        "apitrkr":  str(ts),
        "usrid":    UMANG_UID,
        "mode":     "web",
        "pltfrm":   "linux",
        "did":      str(ts),
        "deptid":   "317",
        "formtrkr": "0",
        "srvid":    "1519",
        "subsid":   "0",
        "subsid2":  "0",
    }

def onorc_post_api(url, payload):
    headers = get_onorc_headers()
    encrypted_data = encrypt(payload)
    r = requests.post(url, headers=headers, data=encrypted_data, timeout=25)
    if r.status_code != 200:
        raise Exception(f"HTTP {r.status_code}")
    return decrypt(r.text)

# ==================== ONORC API CALLS ====================
def onorc_get_ration_card(ration_card_id):
    url = "https://apigw.umangapp.in/onorcApi/ws1/getrationcard"
    payload = {
        **onorc_base_body(),
        "id": ration_card_id,
        "sessionId": str(int(time.time() * 1000)),
        "userName": "umang",
        "idType": "R",
        "token": "Um@93259@",
    }
    return onorc_post_api(url, payload)

# ==================== ROUTE ====================
@app.route("/ration/<ration_card_id>")
def ration_card_info(ration_card_id):
    ration_card_id = ration_card_id.strip()
    if not ration_card_id:
        return jsonify({"found": False, "error": "Ration card number required"}), 400

    result = {
        "found": False,
        "rationCardId": ration_card_id,
    }

    try:
        response = onorc_get_ration_card(ration_card_id)
        
        if response.get("rs") == "S" and response.get("pd"):
            pd = response["pd"]
            result["found"] = True
            
            # Card details
            result["cardDetails"] = {
                "rationCardId": pd.get("rcId"),
                "homeState": pd.get("homeStateName"),
                "homeStateCode": pd.get("homeStateCode"),
                "district": pd.get("homeDistName"),
                "districtCode": pd.get("districtCode"),
                "fpsId": pd.get("fpsId"),
                "scheme": pd.get("schemeName"),
                "schemeId": pd.get("schemeId"),
                "address": pd.get("address"),
                "allowedOnorc": pd.get("allowed_onorc"),
                "dupUidStatus": pd.get("dup_uid_status"),
            }
            
            # Family members
            if "memberDetailsList" in pd:
                members = pd["memberDetailsList"]
                result["totalMembers"] = len(members)
                result["familyMembers"] = []
                
                for member in members:
                    result["familyMembers"].append({
                        "memberId": member.get("memberId"),
                        "memberName": member.get("memberName"),
                        "uidAvailable": member.get("uid"),
                        "relationship": member.get("releationship_name"),
                        "relationshipCode": member.get("relationship_code"),
                    })
                
                # Find head of family
                for member in members:
                    if member.get("relationship_code") == "1":
                        result["headOfFamily"] = member.get("memberName")
                        break
            
        else:
            result["error"] = response.get("rd", "No data found")
            
    except Exception as e:
        result["error"] = str(e)

    return jsonify(result)

@app.route("/")
def index():
    return jsonify({
        "api": "ONORC Ration Card Info API",
        "usage": "/ration/{ration_card_id}",
        "example": "/ration/214740704824",
        "status": "running"
    })

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
