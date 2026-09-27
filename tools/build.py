#!/usr/bin/env python3
"""康軒國小英語教學宜蘭資訊網：加密建置工具

網站內容（ITEMS / FESTS / TOOLS）以 AES-256-GCM 加密後嵌入頁面，
內容金鑰為隨機產生，再以每個「登入答案」經 PBKDF2-SHA256 導出的金鑰各包一份（slots），
任一答案都能解開。明文資料 data.json 不放進儲存庫。
SITE_PW 可放多個答案，用 | 分隔，例如 SITE_PW='答案一|答案二'。

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
HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "site.template.html")
MARK = re.compile(r"/\*ENC\*/.*?/\*/ENC\*/", re.S)

def norm(pw): return re.sub(r"\s+", "", unicodedata.normalize("NFC", pw)).lower().encode()
def key(pw, salt, it): return pbkdf2_hmac("sha256", norm(pw), salt, it, 32)
b64 = lambda b: base64.b64encode(b).decode()

def build(data_path, out_page, out_artifact=None):
    answers = [a for a in os.environ["SITE_PW"].split("|") if a.strip()]
    data = json.load(open(data_path, encoding="utf-8"))
    dk, iv = AESGCM.generate_key(256), os.urandom(12)
    ct = AESGCM(dk).encrypt(iv, json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode(), None)
    slots = []
    for a in answers:
        salt, siv = os.urandom(16), os.urandom(12)
        slots.append({"salt": b64(salt), "iv": b64(siv), "wk": b64(AESGCM(key(a, salt, ITER)).encrypt(siv, dk, None))})
    enc = json.dumps({"iter": ITER, "iv": b64(iv), "ct": b64(ct), "slots": slots})
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
    pw = os.environ["SITE_PW"].split("|")[0]
    enc = json.loads(MARK.search(open(page_path, encoding="utf-8").read()).group(0)[7:-8])
    d = base64.b64decode
    for sl in enc["slots"]:
        try:
            dk = AESGCM(key(pw, d(sl["salt"]), enc["iter"])).decrypt(d(sl["iv"]), d(sl["wk"]), None)
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
