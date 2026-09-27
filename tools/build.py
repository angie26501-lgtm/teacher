#!/usr/bin/env python3
"""康軒國小英語教學宜蘭資訊網：加密建置工具

網站內容（ITEMS / FESTS / TOOLS）以 AES-256-GCM 加密後嵌入頁面，
兩題通關問題都要答對。內容金鑰為隨機產生，再以「第1題答案＋第2題答案」
經 PBKDF2-SHA256 導出的金鑰，為每一種可接受的答案組合各包一份（slots）。
SITE_PW 格式：第1題可接受答案用 | 分隔，兩題之間用 ;; 分隔，
例如 SITE_PW='吳耿德|kenny|angie;;哈佛文教社|哈佛文教|哈佛'
解密時只需一組正確答案，例如 SITE_PW='kenny;;哈佛'。明文資料 data.json 不放進儲存庫。

  解密（取回目前內容）：
    SITE_PW=密碼 python3 tools/build.py decrypt index.html data.json
  加密建置（更新網站）：
    SITE_PW=密碼 python3 tools/build.py build data.json index.html [artifact.html]

答案不分大小寫，空白會忽略。
"""
import base64, json, os, re, sys, unicodedata
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import pbkdf2_hmac

ITER = 250_000
Q1_ITER = 100_000
HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "site.template.html")
MARK = re.compile(r"/\*ENC\*/.*?/\*/ENC\*/", re.S)

def norm(pw): return re.sub(r"\s+", "", unicodedata.normalize("NFC", pw)).lower()
def key(a1, a2, salt, it): return pbkdf2_hmac("sha256", (norm(a1) + "\n" + norm(a2)).encode(), salt, it, 32)
b64 = lambda b: base64.b64encode(b).decode()

def build(data_path, out_page, out_artifact=None):
    q1, q2 = [[a for a in part.split("|") if a.strip()] for part in os.environ["SITE_PW"].split(";;")]
    data = json.load(open(data_path, encoding="utf-8"))
    dk, iv, salt = AESGCM.generate_key(256), os.urandom(12), os.urandom(16)
    ct = AESGCM(dk).encrypt(iv, json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(), None)
    slots = []
    for a1 in q1:
        for a2 in q2:
            siv = os.urandom(12)
            slots.append({"iv": b64(siv), "wk": b64(AESGCM(key(a1, a2, salt, ITER)).encrypt(siv, dk, None))})
    enc = {"iter": ITER, "salt": b64(salt), "iv": b64(iv), "ct": b64(ct), "slots": slots}
    if data.get("Q1MSG"):  # 第 1 題答對後的浮動視窗文字，只用第 1 題答案加密
        s1, msg = os.urandom(16), json.dumps(data["Q1MSG"], ensure_ascii=False).encode()
        q1s = []
        for a1 in q1:
            k1, v1 = pbkdf2_hmac("sha256", norm(a1).encode(), s1, Q1_ITER, 32), os.urandom(12)
            q1s.append({"iv": b64(v1), "ct": b64(AESGCM(k1).encrypt(v1, msg, None))})
        enc["q1"] = {"iter": Q1_ITER, "salt": b64(s1), "slots": q1s}
    enc = json.dumps(enc)
    body = MARK.sub(lambda m: "/*ENC*/" + enc + "/*/ENC*/", open(TEMPLATE, encoding="utf-8").read())
    if out_artifact:
        open(out_artifact, "w", encoding="utf-8").write(body)
    cut = body.index("</style>") + len("</style>")
    page = ('<!doctype html>\n<html lang="zh-Hant-TW">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            '<meta name="robots" content="noindex">\n'
            + body[:cut] + "\n</head>\n<body>\n" + body[cut:] + "\n</body>\n</html>\n")
    open(out_page, "w", encoding="utf-8").write(page)
    print(f"built {out_page}: {len(data['ITEMS'])} items")

def decrypt(page_path, out_data):
    a1, a2 = [part.split("|")[0] for part in os.environ["SITE_PW"].split(";;")]
    enc = json.loads(MARK.search(open(page_path, encoding="utf-8").read()).group(0)[7:-8])
    d = base64.b64decode
    k = key(a1, a2, d(enc["salt"]), enc["iter"])
    for sl in enc["slots"]:
        try:
            dk = AESGCM(k).decrypt(d(sl["iv"]), d(sl["wk"]), None)
            break
        except Exception:
            continue
    else:
        sys.exit("答案不正確")
    pt = AESGCM(dk).decrypt(d(enc["iv"]), d(enc["ct"]), None)
    json.dump(json.loads(pt), open(out_data, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"decrypted to {out_data}")

if __name__ == "__main__":
    cmd, *args = sys.argv[1:]
    {"build": build, "decrypt": decrypt}[cmd](*args)
