# duifene_v2.py — 对分易自动签到助手
# 用法: python duifene_v2.py

import ctypes
try: ctypes.windll.shcore.SetProcessDpiAwareness(1)
except: pass

import configparser, json, os, random, re, time, traceback
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from bs4 import BeautifulSoup

# ── 路径 ──
import sys
BASE_DIR = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).parent
USER_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else BASE_DIR
CONFIG_FILE = USER_DIR / "duifenyi.ini"
DEBUG_DIR = USER_DIR / "debug_logs"
LOCATION_FILE = BASE_DIR / "locations.json"

urllib3.disable_warnings()

# ── 会话 ──
session = requests.Session()
session.verify = False
session.mount("https://", HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.5, status_forcelist=[429], allowed_methods=["GET","POST"]), pool_connections=1, pool_maxsize=2))
session.mount("http://", HTTPAdapter(max_retries=Retry(total=1, backoff_factor=0.5), pool_connections=1, pool_maxsize=2))
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"

HOST = "https://www.duifene.com"
MOBILE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 MicroMessenger/8.0.40(0x1800282a) NetType/WIFI Language/zh_CN"

# ── 配色 ──
CB="#f5f6fa"; CC="#ffffff"; CPRI="#3867d6"; CSUC="#20bf6b"; CDAN="#eb3b5a"
CTX="#2d3436"; CT2="#636e72"; CBO="#dfe6e9"; CLB="#1a1a2e"; CLF="#a4b0be"
CWE="#07c160"; CWA="#fdcb6e"

# ── 日志 ──
class Log:
    def __init__(s): s._w = None; s._d = True
    def set(s, w): s._w = w
    def _p(s, lv, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{lv}] {msg}"; print(line)
        if s._w:
            tags = {"INFO":"info","OK":"ok","WARN":"warn","ERROR":"error","DEBUG":"debug"}
            s._w.insert(tk.END, line+"\n", tags.get(lv))
            s._w.see(tk.END); s._w.update_idletasks()
    def i(s,m): s._p("INFO",m)
    def ok(s,m): s._p("OK",m)
    def w(s,m): s._p("WARN",m)
    def e(s,m): s._p("ERROR",m)
    def d(s,m):
        if s._d: s._p("DEBUG",m)
log = Log()

def get_coords(course_name):
    try:
        if LOCATION_FILE.exists():
            locs = json.loads(LOCATION_FILE.read_text(encoding="utf-8"))
            if course_name in locs: c = locs[course_name]; return c.get("lng",""), c.get("lat","")
    except: pass
    return "", ""

# ── 认证 ──
class Auth:
    @staticmethod
    def ok():
        try:
            h = {"Referer": HOST+"/_UserCenter/PC/CenterStudent.aspx", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
            r = session.post(HOST+"/AppCode/LoginInfo.ashx", data="Action=checklogin", headers=h, timeout=10)
            return r.status_code == 200 and r.json().get("msg") == "1"
        except: return False

    @staticmethod
    def pwd(u, p):
        try:
            h = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Referer": HOST+"/AppGate.aspx"}
            session.get(HOST, timeout=10)
            r = session.post(HOST+"/AppCode/LoginInfo.ashx", data=f"action=loginmb&loginname={u}&password={p}", headers=h, timeout=10)
            if r.status_code == 200:
                resp = r.json()
                if resp.get("msgbox") == "登录成功": Auth._save(); return True
                log.e(f"登录失败: {resp.get('msgbox','')}")
            return False
        except Exception as ex: log.e(f"登录: {ex}"); return False

    @staticmethod
    def wx(link):
        m = re.search(r"(?<=code=)[A-Za-z0-9]{32}", link)
        if not m: log.e("无法提取授权码"); return False
        session.cookies.clear()
        r = session.get(f"{HOST}/P.aspx?authtype=1&code={m.group(0)}&state=1", timeout=10)
        if r and r.status_code == 200: Auth._save(); return True
        log.e("微信登录失败"); return False

    @staticmethod
    def _save():
        ck = "; ".join(f"{k}={v}" for k,v in session.cookies.items())
        config["INFO"] = {"cookie": ck}
        with open(CONFIG_FILE, "w") as f: config.write(f)
        log.i("Cookie已保存")

    @staticmethod
    def load():
        if not CONFIG_FILE.exists(): return False
        try:
            config.read(CONFIG_FILE); ck = config.get("INFO","cookie",fallback="")
            if not ck or ck == "1=1": return False
            for p in ck.split("; "):
                if "=" in p: k,v = p.split("=",1); session.cookies[k]=v
            log.i("已加载本地Cookie"); return True
        except: return False

# ── 课程 ──
class Course:
    @staticmethod
    def list():
        try:
            h = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Referer": HOST+"/_UserCenter/PC/CenterStudent.aspx"}
            r = session.post(HOST+"/_UserCenter/CourseInfo.ashx", data="action=getstudentcourse&classtypeid=2", headers=h, timeout=10)
            if r.status_code != 200: return None
            d = r.json()
            if isinstance(d, list): return d
            if isinstance(d, dict):
                for k in ["data","list","courses","items"]:
                    if k in d and isinstance(d[k],list): return d[k]
            return None
        except Exception as ex: log.e(f"课程列表: {ex}"); return None

    @staticmethod
    def uid():
        try:
            r = session.get(HOST+"/_UserCenter/MB/index.aspx", timeout=10)
            if r.status_code != 200: return None
            soup = BeautifulSoup(r.text, "lxml")
            for eid in ["hidUID","hidUid","hidUserId","hidSID","studentId"]:
                e = soup.find(id=eid)
                if e and e.get("value"): return e.get("value")
            for inp in soup.find_all("input", type="hidden"):
                n = (inp.get("name") or "").lower()
                if any(x in n for x in ["uid","userid","studentid"]): return inp.get("value")
            return None
        except: return None

# ── 签到 API ──
class CI:
    done = []
    _url = None; _data = None; _method = "POST"

    @classmethod
    def rst(cls): cls.done.clear(); cls._url = None; cls._data = None

    @classmethod
    def mark_done(cls, rid):
        if rid and rid not in cls.done: cls.done.append(rid)

    @classmethod
    def disc(cls, cid):
        if cls._url: return cls._url
        page_url = f"{HOST}/_CheckIn/PC/StudentNoCheckCount.aspx?classid={cid}"
        uid = None
        try:
            r = session.get(page_url, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                for eid in ["hidUID","hidUid","hidUserId","hidSID","studentId","HidStudentID"]:
                    e = soup.find(id=eid)
                    if e and e.get("value"): uid = e.get("value"); break
                if not uid:
                    for inp in soup.find_all("input", type="hidden"):
                        n = (inp.get("name") or "").lower()
                        if any(x in n for x in ["studentid","uid"]): uid = inp.get("value"); break
                if not uid: uid = Course.uid()
        except: pass
        if not uid: log.e("无法获取学生ID"); return None

        h = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
             "Referer": "https://www.duifene.com/_CheckIn/PC/StudentNoCheckCount.aspx",
             "X-Requested-With": "XMLHttpRequest", "Origin": "https://www.duifene.com",
             "Accept": "application/json, text/javascript, */*; q=0.01"}
        base = HOST + "/_CheckIn/MBCount.ashx"
        ps = f"action=getstudentinlogbyday&classid={cid}&studentid={uid}"
        try:
            r = session.post(base, data=ps, headers=h, timeout=10)
            if r.status_code == 200:
                j = r.json()
                if "rows" in j: cls._url=base; cls._data=ps; cls._method="POST"; return base
        except: pass
        log.e("API调用失败"); return None

    @classmethod
    def fetch(cls, cid):
        u = cls.disc(cid)
        if not u: return None
        try:
            h = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                 "Referer": f"{HOST}/_UserCenter/MB/index.aspx"}
            d = cls._data.format(c=cid)
            r = session.post(u, data=d, headers=h, timeout=10) if cls._method=="POST" else session.get(f"{u}?{d}", headers=h, timeout=10)
            if r.status_code != 200: return None
            resp = r.json()
            if resp.get("msg") != "1": return None
            return resp.get("rows",[])
        except Exception as ex: log.e(f"获取签到: {ex}"); return None

    @classmethod
    def pend(cls, rows):
        if not rows: return None
        now = datetime.now()
        for r in rows:
            rid = r.get("ID","")
            if rid in cls.done: continue
            if r.get("CheckInStatus","")!="" or r.get("CheckInDate","")!="" or r.get("StudentID","")!="": continue
            if r.get("StatusID","")=="1" or r.get("StatusName","")=="出勤": continue
            if r.get("CanApply","0")!="1": continue
            limit = r.get("ApplyLimitDate","")
            if limit:
                try:
                    if now > datetime.strptime(limit, "%Y/%m/%d %H:%M:%S"): continue
                except: pass
            created = r.get("CreaterDate","")
            if created:
                try:
                    if (now - datetime.strptime(created, "%Y/%m/%d %H:%M:%S")).total_seconds() > 1800: continue
                except: pass
            return r
        return None

    @classmethod
    def code(cls, uid, code):
        try:
            h = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                 "Referer": HOST+"/_CheckIn/MB/CheckInStudent.aspx?moduleid=16&pasd="}
            r = session.post(HOST+"/_CheckIn/CheckIn.ashx",
                           data=f"action=studentcheckin&studentid={uid}&checkincode={code}", headers=h, timeout=10)
            if r.status_code == 200:
                try:
                    msg = r.json().get("msgbox","")
                    if "成功" in msg: return True, msg
                    return False, f"签到未成功: {msg}"
                except: return False, "签到响应异常"
            return False, f"签到请求失败 HTTP {r.status_code}"
        except Exception as ex: return False, f"签到异常: {ex}"

    @classmethod
    def qr(cls, ci):
        try:
            r = session.get(f"{HOST}/_CheckIn/MB/QrCodeCheckOK.aspx?state={ci}", timeout=10)
            if r.status_code != 200: return False, f"二维码请求失败 HTTP {r.status_code}"
            soup = BeautifulSoup(r.text, "lxml")
            for eid in ["DivOK","divok","divOK"]:
                e = soup.find(id=eid)
                if e and "签到成功" in e.get_text(): return True, "签到成功"
            text = soup.get_text()
            if "签到成功" in text: return True, "签到成功"
            if "非微信" in text: return False, "非微信链接登录, 无法二维码签到"
            return False, f"二维码签到未成功: {text[:50]}"
        except Exception as ex: return False, f"二维码签到异常: {ex}"

    @classmethod
    def loc(cls, uid, lng, lat, cid, tcid):
        try:
            lng = round(float(lng)+random.uniform(-0.000089,0.000089),8)
            lat = round(float(lat)+random.uniform(-0.000089,0.000089),8)
            orig_ua = session.headers.get("User-Agent","")
            session.headers["User-Agent"] = MOBILE_UA
            h = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                 "Referer": HOST+"/_CheckIn/MB/CheckInStudent.aspx?moduleid=16&pasd=",
                 "X-Requested-With": "XMLHttpRequest"}
            data = f"action=signin&cid={cid}&tcid={tcid}&sid={uid}&latitude={lat}&longitude={lng}"
            r = session.post(HOST+"/_CheckIn/CheckInRoomHandler.ashx", data=data, headers=h, timeout=10)
            session.headers["User-Agent"] = orig_ua
            if r.status_code == 200:
                try:
                    msg = r.json().get("msgbox","")
                    if "成功" in msg: return True, msg
                    return False, f"签到未成功: {msg}"
                except: return False, "签到响应异常"
            return False, f"签到请求失败 HTTP {r.status_code}"
        except Exception as ex: return False, f"签到异常: {ex}"

    @classmethod
    def lc(cls, ci, cid):
        orig_ua = session.headers.get("User-Agent","")
        session.headers["User-Agent"] = MOBILE_UA
        try:
            url = f"{HOST}/_CheckIn/MB/TeachCheckIn.aspx?classid={cid}&temps=0&checktype=3&isrefresh=0&timeinterval=0&roomid=0&match="
            r = session.get(url, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "lxml")
                lng = lat = None
                for eid in ["HFRoomLongitude","hfroomlongitude"]:
                    e = soup.find(id=eid)
                    if e and e.get("value"): lng = e.get("value")
                for eid in ["HFRoomLatitude","hfroomlatitude"]:
                    e = soup.find(id=eid)
                    if e and e.get("value"): lat = e.get("value")
                if lng and lat: return lng, lat
        except: pass
        finally:
            session.headers["User-Agent"] = orig_ua
        return "", ""

# ── 监控循环 ──
class Loop:
    def __init__(s): s.r=False; s.ci=""; s.cn=""; s._rt=None; s._cid=""; s._delay=0; s._pending=None; s._tick=0

    def start(s, ci, cn, rt, cid="", delay=0):
        s.r=True; s.ci=ci; s.cn=cn; s._rt=rt; s._cid=cid; s._delay=delay
        s._pending=None; s._tick=0; CI.rst()
        log.i(f"监听【{cn}】签到, 延迟{delay}秒"); s._poll()

    def stop(s): s.r=False; log.i("已停止")

    def _poll(s):
        if not s.r: return
        try:
            if not Auth.ok(): log.w("登录失效"); s.r=False; return
            s._tick += 1
            rows = CI.fetch(s.ci)
            if rows is None:
                if s._tick % 10 == 1: log.i("持续监控中...")
            else:
                p = CI.pend(rows)
                if p is None:
                    if s._tick % 10 == 1: log.i("持续监控中...")
                else:
                    cid=p.get("ID",""); ct=p.get("CheckInType",""); cd=p.get("CheckInCode","")
                    nm={"1":"数字码","2":"二维码","3":"定位"}
                    CI.mark_done(cid)
                    log.i(f"发现待签到! ID:{cid} 类型:{nm.get(ct,ct)} 码:{cd or '无'}")
                    if s._delay > 0 and not s._pending:
                        s._pending = (ct, p)
                        log.i(f"将在 {s._delay} 秒后自动签到...")
                        if s._rt: s._rt.after(s._delay * 1000, s._do_pending)
                    else:
                        ok, msg = s._do(ct, p)
                        if ok: log.ok(msg)
                        elif "已结束" in msg or "没有正在" in msg: pass
                        else: log.e(msg)
        except Exception as ex: log.e(f"监控异常: {ex}"); log.d(traceback.format_exc())
        if s.r and s._rt: s._rt.after(2000, s._poll)

    def _do_pending(s):
        if s._pending:
            ct, p = s._pending; s._pending = None
            cid = p.get("ID","")
            ok, msg = s._do(ct, p)
            if ok: log.ok(msg)
            elif "已结束" in msg or "没有正在" in msg: pass
            else: log.e(msg)

    def _do(s, ct, info):
        uid = Course.uid()
        if not uid: return False, "无法获取用户ID"
        if ct == "1":
            c = info.get("CheckInCode","")
            if c: return CI.code(uid, c)
            return False, "未获取到签到码"
        elif ct == "2":
            ci = info.get("ID","")
            if ci: return CI.qr(ci)
            return False, "未获取到签到ID"
        elif ct == "3":
            lng = info.get("Longitude","") or info.get("longitude","")
            lat = info.get("Latitude","") or info.get("latitude","")
            if not lng or not lat: lng, lat = CI.lc(info.get("ID",""), s.ci)
            if not lng or not lat: lng, lat = get_coords(s.cn)
            if not lng or not lat: lng, lat = "114.39437", "22.70462"
            return CI.loc(uid, lng, lat, s._cid, s.ci)
        return False, f"未知签到类型: {ct}"

config = configparser.ConfigParser()
loop = Loop()

# ── GUI ──
class App:
    def __init__(s, rt):
        s.rt = rt; s.rt.title("对分易签到助手"); s.rt.configure(bg=CB)
        s.rt.resizable(True, True); s.rt.minsize(960, 680)
        s._cs = []; ttk.Style().theme_use("clam"); s._ui(); s._init()

    def _ui(s):
        hd = tk.Frame(s.rt, bg=CPRI, height=48); hd.pack(fill=tk.X); hd.pack_propagate(False)
        tk.Label(hd, text="对分易签到助手", font=("Microsoft YaHei UI",16,"bold"), bg=CPRI, fg="white").pack(side=tk.LEFT, padx=20, pady=10)
        s._sv = tk.StringVar(value="● 就绪")
        s._sl = tk.Label(hd, textvariable=s._sv, font=("Microsoft YaHei UI",11), bg=CPRI, fg="#a0c4ff"); s._sl.pack(side=tk.RIGHT, padx=20, pady=10)
        bd = tk.Frame(s.rt, bg=CB); bd.pack(fill=tk.BOTH, expand=True, padx=16, pady=12)
        lf = tk.Frame(bd, bg=CB, width=350); lf.pack(side=tk.LEFT, fill=tk.Y, padx=(0,12)); lf.pack_propagate(False)

        lc = tk.Frame(lf, bg=CC, highlightbackground=CBO, highlightthickness=1, padx=16, pady=14); lc.pack(fill=tk.X)
        tk.Label(lc, text="账号登录", font=("Microsoft YaHei UI",14,"bold"), bg=CC, fg=CTX).pack(anchor=tk.W)
        nb = ttk.Notebook(lc); t1=ttk.Frame(nb); t2=ttk.Frame(nb)
        nb.add(t1, text="微信扫码登录"); nb.add(t2, text="账号密码登录"); nb.pack(fill=tk.X, pady=(10,0))

        wf = tk.Frame(t1, bg=CC); wf.pack(fill=tk.X, padx=6, pady=(10,4))
        tk.Label(wf, text="支持数字码 + 二维码 + 定位签到", font=("Microsoft YaHei UI",10), bg=CC, fg=CT2).pack()
        s._le = tk.Entry(wf, font=("Microsoft YaHei UI",12), relief=tk.FLAT, bg="#f1f2f6", insertbackground=CPRI); s._le.pack(fill=tk.X, pady=(8,4), ipady=6)
        s._le.insert(0, "粘贴微信授权链接到这里..."); s._le.configure(fg=CT2)
        s._le.bind("<FocusIn>", lambda e: s._clr(s._le,"粘贴微信授权链接到这里...")); s._le.bind("<FocusOut>", lambda e: s._rst(s._le,"粘贴微信授权链接到这里..."))
        tk.Button(wf, text="微信登录", command=s._wx, font=("Microsoft YaHei UI",12,"bold"), bg=CWE, fg="white", relief=tk.FLAT, cursor="hand2", activebackground="#06ad56", activeforeground="white", padx=24, pady=6).pack(pady=4)

        help_text = (
            "使用说明:\n"
            "1. 电脑微信打开以下链接并发送:\n"
            "https://open.weixin.qq.com/connect/oauth2/authorize?appid=wx1b5650884f657981"
            "&redirect_uri=https://www.duifene.com/_FileManage/PdfView.aspx"
            "?file=https%3A%2F%2Ffs.duifene.com%2Fres%2Fr2%2Fu6106199%2F"
            "%E5%AF%B9%E5%88%86%E6%98%93%E7%99%BB%E5%BD%95_876c9d439ca68ead389c.pdf"
            "&response_type=code&scope=snsapi_userinfo&connect_redirect=1#wechat_redirect\n\n"
            "2. 点击进入链接，右上角 ... → 复制链接\n"
            "3. 粘贴到上方输入框，点击登录"
        )
        ht = tk.Text(wf, font=("Microsoft YaHei UI",9), bg=CC, fg=CT2, relief=tk.FLAT, height=7, wrap=tk.WORD, borderwidth=0, cursor="arrow")
        ht.insert("1.0", help_text); ht.configure(state=tk.DISABLED); ht.pack(fill=tk.X, pady=(8,0))

        pf = tk.Frame(t2, bg=CC); pf.pack(fill=tk.X, padx=6, pady=(10,4))
        tk.Label(pf, text="不支持二维码签到", font=("Microsoft YaHei UI",10), bg=CC, fg=CDAN).pack()
        for lb, vn, sh in [("账号","_ue",""),("密码","_pe","*")]:
            tk.Label(pf, text=lb, font=("Microsoft YaHei UI",11,"bold"), bg=CC, fg=CTX).pack(anchor=tk.W, pady=(8,2))
            en = tk.Entry(pf, font=("Microsoft YaHei UI",12), show=sh, relief=tk.FLAT, bg="#f1f2f6", insertbackground=CPRI); en.pack(fill=tk.X, ipady=6); setattr(s, vn, en)
        tk.Button(pf, text="登录", command=s._pwd, font=("Microsoft YaHei UI",12,"bold"), bg=CPRI, fg="white", relief=tk.FLAT, cursor="hand2", activebackground="#2751c0", activeforeground="white", padx=24, pady=6).pack(pady=(10,4))

        df = tk.Frame(lc, bg=CC); df.pack(fill=tk.X, pady=(10,0))
        tk.Label(df, text="签到延迟（检测到后等待N秒再签，0=立即）", font=("Microsoft YaHei UI",10), bg=CC, fg=CT2).pack(anchor=tk.W)
        s._se = tk.Entry(df, font=("Microsoft YaHei UI",12), relief=tk.FLAT, bg="#f1f2f6", width=6, insertbackground=CPRI); s._se.insert(0,"0"); s._se.pack(anchor=tk.W, ipady=4)

        cc = tk.Frame(lf, bg=CC, highlightbackground=CBO, highlightthickness=1, padx=16, pady=14); cc.pack(fill=tk.X, pady=(12,0))
        tk.Label(cc, text="课程选择", font=("Microsoft YaHei UI",14,"bold"), bg=CC, fg=CTX).pack(anchor=tk.W)
        s._cv = tk.StringVar(); s._co = ttk.Combobox(cc, textvariable=s._cv, state="readonly", font=("Microsoft YaHei UI",12)); s._co.pack(fill=tk.X, pady=(10,8), ipady=2)
        br = tk.Frame(cc, bg=CC); br.pack(fill=tk.X)
        s._sb = tk.Button(br, text="▶  开始监听", command=s._go, font=("Microsoft YaHei UI",13,"bold"), bg=CSUC, fg="white", relief=tk.FLAT, state=tk.DISABLED, cursor="hand2", activebackground="#1aa65a", activeforeground="white", padx=16, pady=8); s._sb.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,4))
        s._xb = tk.Button(br, text="■  停止", command=s._stop, font=("Microsoft YaHei UI",13,"bold"), bg=CDAN, fg="white", relief=tk.FLAT, state=tk.DISABLED, cursor="hand2", activebackground="#d1344f", activeforeground="white", padx=16, pady=8); s._xb.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(4,0))

        rp = tk.Frame(bd, bg=CC, highlightbackground=CBO, highlightthickness=1); rp.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        rh = tk.Frame(rp, bg=CC, padx=16, pady=10); rh.pack(fill=tk.X)
        tk.Label(rh, text="运行日志", font=("Microsoft YaHei UI",14,"bold"), bg=CC, fg=CTX).pack(side=tk.LEFT)
        tk.Button(rh, text="清空", command=lambda: s._lb.delete("1.0",tk.END), font=("Microsoft YaHei UI",10), bg=CBO, fg=CTX, relief=tk.FLAT, cursor="hand2", padx=10, pady=2).pack(side=tk.RIGHT)
        tk.Frame(rp, bg=CBO, height=1).pack(fill=tk.X, padx=16)
        lf2 = tk.Frame(rp, bg=CLB, padx=4, pady=4); lf2.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        s._lb = tk.Text(lf2, font=("Cascadia Code",11), wrap=tk.WORD, bg=CLB, fg=CLF, relief=tk.FLAT, borderwidth=0, insertbackground="white", padx=10, pady=8, selectbackground="#3b3b5c")
        sb2 = tk.Scrollbar(lf2, bg=CLB, troughcolor=CLB, activebackground=CPRI); s._lb.configure(yscrollcommand=sb2.set); sb2.configure(command=s._lb.yview)
        sb2.pack(side=tk.RIGHT, fill=tk.Y); s._lb.pack(fill=tk.BOTH, expand=True)
        for t, c in [("info","#74b9ff"),("ok","#00b894"),("warn","#fdcb6e"),("error","#ff7675"),("debug","#636e72")]: s._lb.tag_configure(t, foreground=c)
        log.set(s._lb)

    def _clr(s, e, ph):
        if e.get()==ph: e.delete(0,tk.END); e.configure(fg=CTX)
    def _rst(s, e, ph):
        if e.get()=="": e.insert(0,ph); e.configure(fg=CT2)
    def _st(s, tx, cl): s._sv.set(tx); s._sl.configure(fg=cl)

    def _init(s):
        if not CONFIG_FILE.exists():
            config["INFO"]={"cookie":"1=1"}
            with open(CONFIG_FILE,"w") as f: config.write(f)
            try: session.get(HOST, timeout=10)
            except: log.w("无法连接对分易"); return
        if Auth.load():
            if Auth.ok(): s._rf()
            else: log.i("Cookie过期，请重新登录")
        else: log.i("未找到Cookie，请登录")

    def _wx(s):
        lnk = s._le.get().strip()
        if not lnk or "粘贴微信" in lnk: messagebox.showerror("错误","请粘贴微信授权链接"); return
        s._st("登录中...", CWA)
        if Auth.wx(lnk): s._st("已登录", CSUC); s._rf()
        else: s._st("登录失败", CDAN)

    def _pwd(s):
        u=s._ue.get().strip(); p=s._pe.get().strip()
        if not u or not p: messagebox.showerror("错误","请输入账号和密码"); return
        s._st("登录中...", CWA)
        if Auth.pwd(u,p): s._st("已登录", CSUC); messagebox.showinfo("提示","登录成功"); s._rf()
        else: s._st("登录失败", CDAN)

    def _rf(s):
        cs = Course.list()
        if cs:
            s._cs=cs; s._co["values"]=tuple(c.get("CourseName","未知") for c in cs)
            if cs: s._co.set(cs[0].get("CourseName",""))
            s._sb.configure(state=tk.NORMAL); s._st(f"已加载 {len(cs)} 门课程", CSUC)
        else: s._st("获取课程失败", CDAN)

    def _go(s):
        nm = s._cv.get()
        if not nm: messagebox.showerror("错误","请选择课程"); return
        ci=""; cid=""
        for c in s._cs:
            if c.get("CourseName")==nm: ci=c.get("TClassID",""); cid=c.get("CourseID",""); break
        if not ci: log.e(f"未找到课程'{nm}'的TClassID"); return
        s._sb.configure(state=tk.DISABLED); s._xb.configure(state=tk.NORMAL)
        s._st(f"监控中: {nm}", CPRI); s._lb.delete("1.0",tk.END)
        loop.start(ci, nm, s.rt, cid, int(s._se.get() or "0"))

    def _stop(s):
        loop.stop(); s._sb.configure(state=tk.NORMAL); s._xb.configure(state=tk.DISABLED)
        s._st("已停止", CT2)

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
