priv = RSA.import_key(PRIVATE_KEY)
    rsa = PKCS1_OAEP.new(priv, hashAlgo=SHA256)
    key = rsa.decrypt(base64.b64decode(parts[0]))
    iv = rsa.decrypt(base64.b64decode(parts[1]))
    ct = base64.b64decode(parts[2])
    pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    return json.loads(pt.decode())


def headers():
    return {
        "x-api-key": API_KEY,
        "content-type": "application/json",
        "accept": "application/json",
        "deptid": DEPT_ID,
        "srvid": SRV_ID,
        "subsid": "0",
        "subsid2": "0",
        "formtrkr": "0",
        "tenantid": "",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
        "origin": "https://web.umang.gov.in",
        "referer": "https://web.umang.gov.in/",
        "accept-language": "en-IN,en-GB;q=0.9,en;q=0.8",
    }


def base_payload(ration_id: str) -> dict:
    # Exact field names from decrypted successful HAR request
    ts = str(int(time.time() * 1000) % 1000000)
    return {
        "tkn": UMANG_TKN,
        "trkr": ts,
        "lang": "en",
        "lat": "21",
        "lon": "90",
        "lac": "90",
        "usag": "90",
        "apitrkr": ts,
        "usrid": UMANG_UID,
        "mode": "web",
        "pltfrm": "linux",
        "did": ts,
        "deptid": DEPT_ID,
        "formtrkr": "0",
        "srvid": SRV_ID,
        "subsid": "0",
        "subsid2": "0",
        "id": str(ration_id).strip(),
        "sessionId": SESSION_ID,
        "userName": "umang",
        "idType": "R",
        "token": SERVICE_TOKEN,
    }


def fetch_ration(ration_id: str) -> dict:
    payload = base_payload(ration_id)
    enc = encrypt(payload)
    r = requests.post(RATION_URL, headers=headers(), data=enc, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
    raw = r.text.strip()
    # response is encrypted envelope
    if ":" in raw and not raw.startswith("{"):
        return decrypt(raw)
    # sometimes plain json
    return r.json()


@app.route("/Ration")
def ration():
    rid = (request.args.get("id") or "").strip()
    if not rid:
        return jsonify({"ok": False, "error": "id required e.g. /Ration?id=214740704824"}), 400
    try:
        data = fetch_ration(rid)
        return jsonify({"ok": True, "id": rid, "data": data})
    except Exception as e:
        return jsonify({"ok": False, "id": rid, "error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "umang-ration"})


@app.route("/")
def index():
    return jsonify({
        "api": "Umang ONORC Ration Card",
        "usage": "/Ration?id=RATION_CARD_ID",
        "example": "/Ration?id=214740704824",
        "source": "apigw.umangapp.in/onorcApi/ws1/getrationcard",
    })


if name == "main":
    app.run(host="0.0.0.0", port=5000, debug=False)
