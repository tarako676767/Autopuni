#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ぷにぷに 自動周回 Web API サーバー (FastAPI)
- 本物の暗号化・ゲームサーバー通信ロジックを保持
- ログイン・周回・アカウント情報取得のエンドポイントを提供
- SSE (Server-Sent Events) によるリアルタイムログストリーミング
"""

import asyncio
import base64
import hashlib
import json
import random
import re
import time
import uuid
import zlib
from typing import Dict, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs

from Crypto.Cipher import AES
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import requests
import uvicorn

# ============================================================================
# 定数設定
# ============================================================================

AESK = bytes.fromhex('a865d7e5e2458f8ce1b5ecd087e54594')
K = b'0bk2kvtFE2'
APKEY = 'a-zrhgm09pgcgjc1iv9cxvpk3xm9b0ynyo4u00sny6bjq10nrx3up2yrhjnq2lhg'
SIGNATURE = ('s4X9CoyxGma3kGuAp5woThgvBX3dCi77Slh5RcOo6ybmMTt0J4CGiZwyiCsil7P3'
             'MVgjiVt+kGE1MqvttCXLB+hlOpyTkJp5a78TXthBNVw=')
GS = 'https://gameserver.yw-p.com'
L5 = 'https://api.level5-id.com'

MODEL = 'GA00747-UK'
OSVER = '9'
APPVER = '4.174.0'
BATTERY = {'level': 100, 'state': 3, 'technology': 'Li-poly', 'temperature': 261, 'voltage': 4300}

UA = 'Dalvik/2.1.0 (Linux; U; Android %s; %s Build/PI) com.Level5.YWP/%s' % (OSVER, MODEL, APPVER)
HDR = {'Accept-Encoding': 'identity', 'User-Agent': UA, 'Accept': 'application/json',
       'Content-Type': 'application/json', 'Connection': 'Keep-Alive'}

RC = {0: 'OK', -1: 'IPブロック/復号不可', 20: 'appVerかマスタ版が古い', 30: '署名の不整合',
      32: 'tokenズレ', 37: 'チュートリアル未完了', 101: 'マスタ版が現行と違う', 202: 'BAN'}

GAME_CONST = [
    {"constType": 5, "mstKey": "blockComboAdjustNumA", "mstValue": "0.051800"},
    {"constType": 5, "mstKey": "blockComboAdjustNumB", "mstValue": "0.995500"},
    {"constType": 5, "mstKey": "blockSizeAdjustA", "mstValue": "0.000800"},
    {"constType": 5, "mstKey": "blockSizeAdjustB", "mstValue": "0.077000"},
    {"constType": 5, "mstKey": "blockSizeAdjustC", "mstValue": "-0.058500"},
    {"constType": 5, "mstKey": "blockSizeAdjustSkillA", "mstValue": "5.780200"},
    {"constType": 5, "mstKey": "blockSizeAdjustSkillB", "mstValue": "-2.201000"},
    {"constType": 5, "mstKey": "blockSizeAdjustSkillC", "mstValue": "1.000000"},
    {"constType": 5, "mstKey": "blockSizeRate1", "mstValue": "0.019300"},
    {"constType": 5, "mstKey": "blockSizeRate2", "mstValue": "0.058600"},
    {"constType": 5, "mstKey": "blockSizeRate3", "mstValue": "0.137900"},
    {"constType": 5, "mstKey": "comboEnableSec", "mstValue": "3.000000"},
    {"constType": 5, "mstKey": "comboEnableSize", "mstValue": "2"},
    {"constType": 5, "mstKey": "damageSwitchSize", "mstValue": "3"},
    {"constType": 5, "mstKey": "feverDamageAdjustNum", "mstValue": "0.100000"},
    {"constType": 5, "mstKey": "feverScoreAdjustNum", "mstValue": "0.100000"},
    {"constType": 5, "mstKey": "saBlockSizeAdjustSubA", "mstValue": "0.006200"},
    {"constType": 5, "mstKey": "saBlockSizeAdjustSubB", "mstValue": "-0.024500"},
    {"constType": 5, "mstKey": "saBlockSizeAdjustSubC", "mstValue": "0.416900"},
    {"constType": 5, "mstKey": "scoreAdjustNumA", "mstValue": "11.223000"},
    {"constType": 5, "mstKey": "scoreAdjustNumB", "mstValue": "0.047700"},
    {"constType": 5, "mstKey": "skillGaugeIncrementSize1", "mstValue": "0.100000"},
    {"constType": 5, "mstKey": "skillGaugeIncrementSize2", "mstValue": "1.200000"},
    {"constType": 5, "mstKey": "skillGaugeIncrementSize3", "mstValue": "2.400000"},
]

# ============================================================================
# 暗号化・復号化関数
# ============================================================================

def salt20(body):
    return hashlib.sha1(K + hashlib.sha1(K + b' ' + body).digest()).digest()

def enc(body):
    pt = salt20(body) + body
    p = 16 - len(pt) % 16
    pt += bytes([p]) * p
    return base64.urlsafe_b64encode(AES.new(AESK, AES.MODE_ECB).encrypt(pt)).decode().rstrip('=')

def dec(s):
    s = s.strip()
    ct = base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
    pt = AES.new(AESK, AES.MODE_ECB).decrypt(ct)
    rest = pt[20:]
    g = rest.find(b'\x1f\x8b')
    if g >= 0:
        try:
            return zlib.decompress(rest[g:], 47)
        except Exception:
            pass
    try:
        rest = rest[:-pt[-1]]
    except Exception:
        pass
    e = max(rest.rfind(b'}'), rest.rfind(b']'))
    return rest[:e + 1] if e >= 0 else rest

def jbody(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

# ============================================================================
# API通信関数
# ============================================================================

def post_nhn(name, obj, timeout=30, retry=3):
    for attempt in range(1, retry + 1):
        try:
            r = requests.post('%s/%s' % (GS, name), data=enc(jbody(obj)),
                              headers={**HDR, 'Host': 'gameserver.yw-p.com'}, timeout=timeout)
            if r.status_code != 200:
                if attempt < retry:
                    time.sleep(2 ** attempt)
                    continue
                return r.status_code, {'resultCode': -1, '_error': f'HTTP{r.status_code}'}
            try:
                out = dec(r.text)
            except Exception:
                if attempt < retry:
                    time.sleep(2 ** attempt)
                    continue
                return r.status_code, {'resultCode': -1, '_raw': (r.text or '')[:200]}
            try:
                return r.status_code, json.loads(out)
            except Exception:
                if attempt < retry:
                    time.sleep(2 ** attempt)
                    continue
                return r.status_code, {'_raw': out[:300].decode('utf-8', 'replace')}
        except requests.exceptions.Timeout:
            if attempt < retry:
                time.sleep(3 * attempt)
                continue
            return None, {'resultCode': -1, '_error': 'Timeout'}
        except requests.exceptions.ConnectionError:
            if attempt < retry:
                time.sleep(3 * attempt)
                continue
            return None, {'resultCode': -1, '_error': 'ConnectionError'}
    return None, {'resultCode': -1, '_error': 'Max retries exceeded'}

def active(udkey=None, timeout=30):
    p = {'apkey': APKEY, 'device_cd': '%s_%s' % (MODEL, OSVER), 'device_type_cd': 'Android',
         'sign': 'true', 'version': APPVER}
    if udkey:
        p['udkey'] = udkey
    return requests.get('%s/api/v1/active/' % L5, params=p,
                        headers={'User-Agent': UA}, timeout=timeout).json()

def new_udkey():
    return active()['udkey']['value']

def _parse_forms(html):
    out = []
    for fm in re.finditer(r'<form\b[^>]*>(.*?)</form>', html, re.S | re.I):
        block = fm.group(0)
        am = re.search(r'action="([^"]*)"', block, re.I)
        inputs = {}
        for im in re.finditer(r'<input\b[^>]*>', block, re.I):
            nm = re.search(r'name="([^"]*)"', im.group(0), re.I)
            vm = re.search(r'value="([^"]*)"', im.group(0), re.I)
            if nm:
                inputs[nm.group(1)] = vm.group(1) if vm else ''
        out.append({'action': am.group(1) if am else '', 'inputs': inputs})
    return out

def link_email(udkey, email, pw, timeout=25):
    s = requests.Session()
    s.headers.update({'User-Agent': UA, 'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
                      'Accept-Language': 'ja'})
    r = s.get('%s/api/v1/link_account' % L5, params={'apkey': APKEY, 'udkey': udkey},
              allow_redirects=True, timeout=timeout)
    lf = [x for x in _parse_forms(r.text) if any('email' in k.lower() for k in x['inputs'])]
    if not lf:
        raise RuntimeError('ログイン画面が出ない(既に連携済み or メール不正)')
    inp = dict(lf[0]['inputs'])
    inp['form[email]'] = email
    inp['form[password]'] = pw
    r = s.post(urljoin(r.url, lf[0]['action']), data=inp, allow_redirects=True, timeout=timeout)
    ap = [x for x in _parse_forms(r.text) if 'client_id' in x['inputs'] and x['inputs'].get('_method', '') != 'delete']
    if not ap:
        raise RuntimeError('consent画面が出ない(メール/パスが違う?)')
    inp = dict(ap[0]['inputs'])
    inp.setdefault('commit', 'Authorize')
    r2 = s.post(urljoin(r.url, ap[0]['action']), data=inp, allow_redirects=False, timeout=timeout)
    code = (parse_qs(urlparse(r2.headers.get('Location', '')).query).get('code') or [None])[0]
    if not code:
        raise RuntimeError('認可コードが取れない')
    fin = s.get('%s/api/v1/link_account' % L5,
                params={'code': code, 'apkey': APKEY, 'udkey': udkey,
                        'device_cd': '%s_%s' % (MODEL, OSVER), 'device_type_cd': 'Android'},
                timeout=timeout).json()
    if not fin.get('result'):
        raise RuntimeError('連携finalize失敗: %s' % fin)
    return fin

def rows(s):
    if isinstance(s, str):
        s = json.loads(s) if s.startswith('{') else s
    return [r.split('|') for r in (s or '').split('*') if r] if isinstance(s, str) else (s.get('rows') if isinstance(s, dict) else (s or []))

# ============================================================================
# Clientクラス
# ============================================================================

class Client:
    def __init__(self, udkey):
        self.udkey = udkey
        self.gdkey = None
        self.userId = None
        self.token = '0'
        self.mst = 16897
        self.save = {}

    def _active_with_gdkeys(self, retries=6):
        a = active(self.udkey)
        for _ in range(retries):
            if a.get('gdkeys'):
                break
            time.sleep(1.2)
            a = active(self.udkey)
        if not a.get('gdkeys'):
            raise RuntimeError('gdkeyが無い(このudkeyに紐づくゲームデータが無い)')
        return a

    def _enum(self, a):
        gds = a['gdkeys']
        pl = []
        for _ in range(5):
            rc, j = post_nhn('getGdkeyAccounts.nhn', {
                'appVer': APPVER, 'deviceId': self.udkey,
                'gdkeys': [{'gdkey': g['value']} for g in gds],
                'level5UserId': '0', 'mstVersionVer': self.mst, 'osType': 2,
                'userId': '0', 'ywpToken': '0'})
            pl = j.get('udkeyPlayerList') or []
            if len(pl) >= len(gds):
                break
            time.sleep(1.2)
        by_g = {str(p.get('gdkey')): p for p in pl if p.get('gdkey')}
        out = []
        for i, g in enumerate(gds):
            p = by_g.get(g['value'], {})
            out.append({'idx': i, 'userId': p.get('userId'), 'playerName': p.get('playerName'),
                        'gdkey': g['value'], 'gdsig': g['signature']})
        return out

    def init_nhn(self):
        rc, j = post_nhn('init.nhn', {
            'appGuardDeviceId': hashlib.sha256(self.udkey.encode()).hexdigest(),
            'appVer': APPVER, 'deviceId': self.udkey, 'level5UserId': '0',
            'mstVersionVer': self.mst, 'osType': 2, 'signature': SIGNATURE,
            'userId': '0', 'ywpToken': '0'})
        v = j.get('mstVersionMaster')
        if isinstance(v, int) and v > 0:
            self.mst = v
        return j

    def login(self, userId=None):
        self.init_nhn()
        a = self._active_with_gdkeys()
        accs = self._enum(a)
        sel = None
        if userId is not None:
            sel = next((x for x in accs if str(x['userId']) == str(userId)), None)
            if sel is None:
                raise RuntimeError('userId %s が見つからない' % userId)
        if sel is None:
            sel = accs[0]
        rc, j = post_nhn('login.nhn', {
            'appVer': APPVER, 'batteryInfo': BATTERY, 'deviceId': self.udkey,
            'deviceName': MODEL, 'gdkeySignature': sel['gdsig'], 'gdkeyValue': sel['gdkey'],
            'isL5IDLinked': 1,
            'level5UserId': sel['gdkey'],
            'modelName': MODEL, 'mstVersionVer': self.mst, 'osType': 2, 'osVersion': OSVER,
            'signNonce': a['sign_nonce'], 'signTimestamp': str(a['sign_timestamp']),
            'signature': SIGNATURE, 'udkeySignature': a['udkey']['signature'],
            'udkeyValue': self.udkey, 'userId': sel['userId'], 'ywpToken': '0'})
        if j.get('resultCode') != 0:
            code = j.get('resultCode')
            error_desc = RC.get(code, '不明なエラー')
            error_detail = j.get('_raw') or j.get('_error') or j.get('dialogMsg') or ''
            raise RuntimeError('login失敗: rc=%s (%s) %s' % (code, error_desc, error_detail[:100]))
        self.gdkey, self.userId, self.token = sel['gdkey'], sel['userId'], j.get('token')
        self.save = j
        return j

    def call(self, name, extra=None):
        if not self.token or self.token == '0':
            raise RuntimeError('先に login() してください')
        body = {'activeDeckId': 1, 'appVer': APPVER, 'deviceId': self.udkey,
                'level5UserId': self.gdkey, 'mstVersionVer': self.mst, 'osType': 2,
                'token': self.token, 'userId': str(self.userId), 'ywpToken': '0'}
        if extra:
            body.update(extra)
        rc, j = post_nhn(name, body)
        t = j.get('token')
        if t and t != 'null':
            self.token = t
        return rc, j

    def build_game_end(self, stageId, battleType, start):
        reqId = start.get('requestId')
        yk = start.get('userYoukaiList') or []
        en = start.get('enemyYoukaiList') or []
        ehp = sum(e.get('hp', 0) for e in en)
        dmg = ehp + random.randint(50, max(ehp // 50, 500)) if ehp else 50000
        users = []
        for i, y in enumerate(yk):
            users.append({
                'damageMax': int(dmg * 0.062) if i == 0 else 0,
                'damageTotal': dmg if i == 0 else 0,
                'eraseNum': 26 if i == 0 else 0,
                'eraseSize': 1711 if i == 0 else 0,
                'eraseSizeMax': 101 if i == 0 else 0,
                'linkSizeMax': 2 if i == 0 else 0,
                'recoveryActual': 0,
                'recoveryMax': 0,
                'sSkillUseNum': 0,
                'skillUseNum': 0,
                'youkaiId': y.get('youkaiId'),
            })
        enemies = []
        for i, e in enumerate(en):
            enemies.append({
                'deadEndOrder': i + 1,
                'deadEndType': 0,
                'dropItemCheckKey': (e.get('lotItemInfoList') or '00000|0').split('|')[0],
                'dropItemFlg': 0,
                'dropItemId': 0,
                'dropTreasureFlg': 0,
                'dropTreasureId': 0,
                'dropYoukaiCheckKey': (e.get('lotYoukaiInfoList') or '00000|0').split('|')[0],
                'dropYoukaiFlg': 0,
                'enemyId': e.get('enemyId'),
                'itemId': 0,
                'useItemLLarge': 0,
                'useItemLarge': 0,
                'useItemMiddle': 0,
                'useItemSmall': 0,
            })
        return {
            'stageId': stageId,
            'battleType': battleType,
            'requestId': str(reqId),
            'damageTotal': dmg,
            'score': min(dmg * 20, 2000000000),
            'userYoukaiResultList': users,
            'enemyYoukaiResultList': enemies,
            'bonusBlockNum': 0,
            'cheatFlg': 0,
            'clearTimeLongSec': 0,
            'clearTimeSec': 29,
            'comboMax': 13,
            'eraseNumTotal': 26,
            'eraseSizeAve': '65.80',
            'eraseSizeMax': 101,
            'eventPoint': 0,
            'eventSubPoint': 0,
            'eventTeamPoint': 0,
            'feverTimeNum': 0,
            'linkSizeMax': 2,
            'pauseAtkNum': 0,
            'recvDamageTotal': 0,
            'resultRecvAtkNum': 0,
            'resultYoukaiHP': 755,
            'scoreLog': '',
            'spMissionIntValue1': 0,
            'suspendFlg': 0,
            'themeResultList': [],
            'ywp_mst_game_const': GAME_CONST,
        }

    def battle(self, stageId, battleType=None, wait=2.0):
        if battleType is None:
            battleType = 6 if str(stageId).startswith(('28805', '28904', '29008', '29304')) else 1
        rc, js = self.call('gameStart.nhn', {'stageId': stageId, 'battleType': battleType,
                                             'battleCode': '', 'retryFlg': 0})
        if js.get('resultCode') != 0:
            return js.get('resultCode'), js
        time.sleep(wait)
        ge = self.build_game_end(stageId, battleType, js)
        return self.call('gameEnd.nhn', ge)

    def info(self):
        d = self.save.get('ywp_user_data')
        if isinstance(d, str):
            d = json.loads(d)
        return d or {}

    def stages(self):
        return {int(r[0]): r for r in rows(self.save.get('ywp_user_stage'))}

# ============================================================================
# FastAPI アプリケーションとモデル定義
# ============================================================================

app = FastAPI(
    title="ぷにぷに 自動周回 API サーバー",
    description="実際のゲームサーバーと通信を行うREST APIサーバーです。",
    version="1.0.0"
)

# CORSを許可（フロントエンドとの通信用）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# メモリ上でのセッション・タスク管理
SESSIONS: Dict[str, Client] = {}
TASKS: Dict[str, Dict[str, Any]] = {}

class LoginRequest(BaseModel):
    email: str
    password: str
    userId: Optional[str] = None

class LoopRequest(BaseModel):
    session_id: str
    stage_id: int
    count: int = 10
    request_delay: float = 0.5
    cooldown: float = 3.0

# ============================================================================
# API エンドポイント
# ============================================================================

@app.post("/api/login", summary="ログイン・連携")
def api_login(req: LoginRequest):
    """UDkeyを取得し、LEVEL5 IDと連携してゲームサーバーにログインします。"""
    try:
        udkey = new_udkey()
        link_email(udkey, req.email, req.password)
        time.sleep(3)
        
        c = Client(udkey)
        c.login(userId=req.userId)
        
        session_id = str(uuid.uuid4())
        SESSIONS[session_id] = c
        
        info = c.info()
        return {
            "status": "success",
            "session_id": session_id,
            "udkey": udkey,
            "user_id": c.userId,
            "player_name": info.get("playerName"),
            "data": info
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/user/info/{session_id}", summary="ユーザー情報・ステージ取得")
def api_get_info(session_id: str):
    """指定されたセッションのユーザー情報および解放済みステージを取得します。"""
    if session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")
    
    c = SESSIONS[session_id]
    return {
        "status": "success",
        "user_id": c.userId,
        "info": c.info(),
        "unlocked_stages": list(c.stages().keys())
    }

@app.post("/api/loop/start", summary="周回タスク開始")
def api_start_loop(req: LoopRequest, background_tasks: BackgroundTasks):
    """バックグラウンドで非同期に自動周回を開始します。"""
    if req.session_id not in SESSIONS:
        raise HTTPException(status_code=404, detail="Session not found")

    c = SESSIONS[req.session_id]
    stages = c.stages()
    if req.stage_id not in stages:
        raise HTTPException(status_code=400, detail=f"Stage {req.stage_id} is not cleared or found")

    task_id = str(uuid.uuid4())
    TASKS[task_id] = {
        "status": "running",
        "progress": 0,
        "total": req.count,
        "success": 0,
        "failed": 0,
        "logs": [],
        "cancel_requested": False
    }

    # バックグラウンド処理を開始
    background_tasks.add_task(
        run_loop_task,
        task_id=task_id,
        client=c,
        stage_id=req.stage_id,
        count=req.count,
        delay=req.request_delay,
        cooldown=req.cooldown
    )

    return {"status": "started", "task_id": task_id}

def run_loop_task(task_id: str, client: Client, stage_id: int, count: int, delay: float, cooldown: float):
    task = TASKS[task_id]
    
    for i in range(1, count + 1):
        if task.get("cancel_requested"):
            task["logs"].append(f"[{i}/{count}] ユーザーにより停止されました。")
            task["status"] = "cancelled"
            break

        rd = delay * random.uniform(0.7, 1.3)
        cd = cooldown * random.uniform(0.7, 1.3)
        
        time.sleep(rd)
        
        try:
            rc, res = client.battle(stage_id)
            code = res.get("resultCode")
            
            if code == 0:
                task["success"] += 1
                ep = res.get("eventPoint", 0)
                msg = f"[{i}/{count}] バトルクリア! (EventPt: {ep})" if ep > 0 else f"[{i}/{count}] バトルクリア!"
                task["logs"].append(msg)
            else:
                task["failed"] += 1
                err_desc = RC.get(code, "不明なエラー")
                task["logs"].append(f"[{i}/{count}] バトル失敗 (rc={code}: {err_desc})")
                if code in [202, 30, 32]:
                    task["logs"].append("致命的なエラーのためタスクを停止します。")
                    task["status"] = "error"
                    break
        except Exception as e:
            task["failed"] += 1
            task["logs"].append(f"[{i}/{count}] エラー発生: {str(e)[:80]}")

        task["progress"] = i
        if i < count and not task.get("cancel_requested"):
            time.sleep(cd)

    if task["status"] == "running":
        task["status"] = "completed"

@app.get("/api/loop/status/{task_id}", summary="タスク進捗確認")
def api_loop_status(task_id: str):
    """実行中の周回タスクの状況およびログを取得します。"""
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Task not found")
    return TASKS[task_id]

@app.post("/api/loop/stop/{task_id}", summary="周回タスク停止")
def api_stop_loop(task_id: str):
    """実行中の周回タスクに停止フラグを送ります。"""
    if task_id not in TASKS:
        raise HTTPException(status_code=404, detail="Task not found")
    TASKS[task_id]["cancel_requested"] = True
    return {"status": "stopping"}

# ============================================================================
# シンプルなWebダッシュボードUI
# ============================================================================

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def index_page():
    return """
    <!DOCTYPE html>
    <html lang="ja">
    <head>
        <meta charset="UTF-8">
        <title>ぷにぷに周回 API コンソール</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 20px; max-width: 800px; margin: 0 auto; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }
            h2 { margin-top: 0; color: #38bdf8; }
            input, button { padding: 10px; margin: 5px 0; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: #fff; width: 100%; box-sizing: border-box; }
            button { background: #0284c7; cursor: pointer; font-weight: bold; border: none; }
            button:hover { background: #0369a1; }
            #console { background: #000; color: #4ade80; padding: 10px; border-radius: 4px; height: 200px; overflow-y: scroll; font-family: monospace; font-size: 13px; }
        </style>
    </head>
    <body>
        <h1>ぷにぷに周回 Web Console</h1>
        
        <div class="card">
            <h2>1. ログイン</h2>
            <input type="email" id="email" placeholder="メールアドレス">
            <input type="password" id="password" placeholder="パスワード">
            <button onclick="login()">ログイン実行</button>
            <div id="loginStatus" style="margin-top: 10px; color: #facc15;"></div>
        </div>

        <div class="card">
            <h2>2. 周回タスク実行</h2>
            <input type="number" id="stageId" placeholder="ステージID (例: 101)">
            <input type="number" id="count" value="10" placeholder="周回回数">
            <button onclick="startLoop()">周回開始</button>
        </div>

        <div class="card">
            <h2>リアルタイムログ</h2>
            <div id="console"></div>
        </div>

        <p><a href="/docs" target="_blank" style="color: #38bdf8;">Swagger APIドキュメント（/docs）を開く</a></p>

        <script>
            let sessionId = "";
            let taskId = "";
            let pollTimer = null;

            function log(msg) {
                const c = document.getElementById("console");
                c.innerHTML += msg + "<br>";
                c.scrollTop = c.scrollHeight;
            }

            async function login() {
                const email = document.getElementById("email").value;
                const password = document.getElementById("password").value;
                document.getElementById("loginStatus").innerText = "ログイン処理中...";
                log("[送信] ログインリクエスト...");

                try {
                    const res = await fetch("/api/login", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ email, password })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        sessionId = data.session_id;
                        document.getElementById("loginStatus").innerText = `成功! プレイヤー名: ${data.player_name} (ID: ${data.user_id})`;
                        log(`[成功] ログイン完了 Session: ${sessionId}`);
                    } else {
                        document.getElementById("loginStatus").innerText = "失敗: " + data.detail;
                        log(`[エラー] ${data.detail}`);
                    }
                } catch (e) {
                    log(`[通信エラー] ${e}`);
                }
            }

            async function startLoop() {
                if (!sessionId) return alert("先にログインしてください");
                const stageId = parseInt(document.getElementById("stageId").value);
                const count = parseInt(document.getElementById("count").value);

                log(`[送信] ステージ ${stageId} 周回開始リクエスト...`);
                try {
                    const res = await fetch("/api/loop/start", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ session_id: sessionId, stage_id: stageId, count: count })
                    });
                    const data = await res.json();
                    if (res.ok) {
                        taskId = data.task_id;
                        log(`[開始] タスクID: ${taskId}`);
                        if (pollTimer) clearInterval(pollTimer);
                        pollTimer = setInterval(pollStatus, 2000);
                    } else {
                        log(`[エラー] ${data.detail}`);
                    }
                } catch (e) {
                    log(`[通信エラー] ${e}`);
                }
            }

            async function pollStatus() {
                if (!taskId) return;
                const res = await fetch(`/api/loop/status/${taskId}`);
                const data = await res.json();
                
                const c = document.getElementById("console");
                c.innerHTML = data.logs.join("<br>");
                c.scrollTop = c.scrollHeight;

                if (data.status === "completed" || data.status === "error" || data.status === "cancelled") {
                    clearInterval(pollTimer);
                    log(`[完了] ステータス: ${data.status} (成功: ${data.success}, 失敗: ${data.failed})`);
                }
            }
        </script>
    </body>
    </html>
    """

# ============================================================================
# メイン実行エントリポイント
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("  ぷにぷに 周回 API サーバーを起動します...")
    print("  Web画面: http://127.0.0.1:8000")
    print("  API仕様書: http://127.0.0.1:8000/docs")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
