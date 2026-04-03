#!/usr/bin/env python3
"""
FTD Snort 2 Local Rule Extractor - SSH CLI 방식
=================================================
FTD에 SSH로 접속 → expert 모드 → sudo bash로 root 획득 후
Snort 2 local rule 파일을 직접 읽어 CSV로 저장.

탐색 순서:
  1. Detection Engine UUID 자동 탐지
  2. 지정한 Intrusion Policy(기본: SOC)의 .rules 파일에서 Local SID 추출
  3. 발견 못할 경우 /ngfw 전체에서 local.rules 파일 탐색

의존성:
    pip install paramiko

사용법:
    python3 fmc_snort2_localrules_via_ssh.py
    python3 fmc_snort2_localrules_via_ssh.py --policy SOC
    python3 fmc_snort2_localrules_via_ssh.py --debug

출력:
    fmc_snort2_local_rules_ssh_YYYYMMDD_HHMMSS.csv  (컬럼: GID, SID, Message, rule)
"""

import argparse
import base64
import csv
import getpass
import gzip
import io
import os
import re
import sys
import time
from datetime import datetime

try:
    import paramiko
except ImportError:
    sys.exit("[!] paramiko 미설치. 다음 명령을 실행하세요: pip install paramiko")

# ──────────────────────────────────────────────
# 설정
# ──────────────────────────────────────────────
FTD_HOST  = "10.0.0.29"
FTD_PORT  = 22
FTD_USER  = "admin"
FTD_PASS  = os.environ.get("FTD_PASS", "zkdlWkd_12!@")
SUDO_PASS = os.environ.get("SUDO_PASS", "zkdlWkd_12!@")

DE_BASE   = "/ngfw/var/sf/detection_engines"
SID_MIN   = 1_000_000
SID_MAX   = 1_999_999

# ──────────────────────────────────────────────
# 사전 컴파일된 정규식
# ──────────────────────────────────────────────
_RE_STRIP  = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')
_RE_SID    = re.compile(r'\bsid\s*:\s*(\d+)\s*;')
_RE_GID    = re.compile(r'\bgid\s*:\s*(\d+)\s*;')
_RE_MSG    = re.compile(r'\bmsg\s*:\s*"([^"]+)"')
_RE_RULE   = re.compile(r'^(alert|drop|pass|log|reject|activate|dynamic)\s+')
_RE_UUID   = re.compile(r'^[0-9a-f-]{36}$')
_RE_PROMPT = re.compile(r'[#$]\s*$')
_RE_SUDO   = re.compile(r'[Pp]assword\s*:')
_RE_NAME   = re.compile(r'#\s*Name\s*:\s*(.+)')


# ──────────────────────────────────────────────
# 인자 파싱
# ──────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="FTD Snort 2 Local Rule 추출기")
    p.add_argument("--policy", "-p", default="SOC", metavar="NAME",
                   help="대상 Intrusion Policy 이름 (기본: SOC)")
    p.add_argument("--host",  default=FTD_HOST)
    p.add_argument("--port",  default=FTD_PORT, type=int)
    p.add_argument("--user",  default=FTD_USER)
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


# ──────────────────────────────────────────────
# 유틸리티
# ──────────────────────────────────────────────
_DEBUG = False

def _debug(msg: str):
    if _DEBUG:
        print(f"  [DEBUG] {msg}")

def _strip_ctrl(text: str) -> str:
    return _RE_STRIP.sub('', text)

def _parse_sid(rule_text: str):
    m = _RE_SID.search(rule_text)
    return int(m.group(1)) if m else None

def _parse_gid(rule_text: str) -> int:
    m = _RE_GID.search(rule_text)
    return int(m.group(1)) if m else 1

def _parse_msg(rule_text: str) -> str:
    m = _RE_MSG.search(rule_text)
    return m.group(1) if m else ""

def _is_snort_rule(line: str) -> bool:
    s = line.strip()
    return bool(s and not s.startswith("#") and _RE_RULE.match(s))


# ──────────────────────────────────────────────
# FTD SSH Shell
# ──────────────────────────────────────────────
class FTDShell:
    def __init__(self, host, port, user, password, sudo_password):
        self._sudo_pass = sudo_password
        self._client    = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print(f"[*] SSH 접속 중: {user}@{host}:{port}")
        try:
            self._client.connect(
                host, port=port, username=user, password=password,
                look_for_keys=False, allow_agent=False, timeout=30
            )
        except paramiko.AuthenticationException:
            sys.exit(f"[!] SSH 인증 실패: {user}@{host}")
        except Exception as e:
            sys.exit(f"[!] SSH 연결 실패: {e}")

        self._shell = self._client.invoke_shell(term="dumb", width=300, height=50)
        self._shell.settimeout(60)
        print("[+] SSH 연결 성공")

    def _recv(self, timeout: float, expect: str) -> str:
        buf = ""
        deadline = time.time() + timeout
        pattern = re.compile(expect, re.MULTILINE)
        while time.time() < deadline:
            if self._shell.recv_ready():
                buf += self._shell.recv(65536).decode("utf-8", errors="replace")
                cleaned = _strip_ctrl(buf)
                if pattern.search(cleaned):
                    return cleaned
            time.sleep(0.15)
        return _strip_ctrl(buf)

    def _send(self, cmd: str):
        _debug(f"send: {cmd!r}")
        self._shell.send(cmd + "\n")
        time.sleep(0.3)

    def setup(self) -> bool:
        self._recv(15, r'>\s*$')
        self._send("expert")
        out = self._recv(20, r'[#$]\s*$')
        if not _RE_PROMPT.search(out):
            print(f"[!] expert 모드 진입 실패. 응답:\n{out[:300]}")
            return False
        print("[+] expert 모드 진입 성공")

        self._send("sudo bash")
        out = self._recv(15, r'([Pp]assword\s*:|[#$]\s*$)')
        if _RE_SUDO.search(out):
            self._send(self._sudo_pass)
            out = self._recv(15, r'[#$]\s*$')

        if _RE_PROMPT.search(out):
            print("[+] root(sudo bash) 획득 성공")
        else:
            print("[!] sudo bash 실패 → admin 권한으로 계속 시도합니다.")

        self._send("export PS1='##SH## '")
        self._recv(5, r'##SH##')
        return True

    def run(self, cmd: str, timeout: float = 60.0) -> str:
        end = "##END##"
        self._send(cmd)
        self._send(f"echo {end}")
        raw = self._recv(timeout, end)
        idx = raw.rfind(end)
        if idx >= 0:
            raw = raw[:idx]
        lines = [
            s for line in raw.splitlines()
            if (s := line.strip()) and "##SH##" not in s
        ]
        first_word = cmd.split()[0] if cmd.split() else ""
        if lines and first_word and lines[0].startswith(first_word):
            lines = lines[1:]
        result = "\n".join(lines)
        _debug(f"run({cmd[:60]!r}) → {result[:200]!r}")
        return result

    def read_file(self, fpath: str, timeout: float = 240.0) -> str:
        """파일 내용을 gzip+base64로 전송 (대용량 파일 대응)"""
        raw = self.run(f"cat '{fpath}' | gzip | base64", timeout=timeout)
        b64 = "".join(
            l.strip() for l in raw.splitlines()
            if l.strip() and not l.strip().startswith("cat") and "##" not in l
        )
        if not b64:
            return ""
        try:
            with gzip.open(io.BytesIO(base64.b64decode(b64))) as gz:
                return gz.read().decode("utf-8", errors="replace")
        except Exception as e:
            _debug(f"read_file 디코드 실패 ({fpath}): {e}")
            return ""

    def close(self):
        try:
            self._shell.close()
            self._client.close()
        except Exception:
            pass


# ──────────────────────────────────────────────
# Detection Engine + Policy 탐색
# ──────────────────────────────────────────────
def find_de_uuid(shell: FTDShell) -> str:
    out = shell.run(f"ls {DE_BASE}/")
    uuids = [l.strip() for l in out.splitlines() if _RE_UUID.match(l.strip())]
    if not uuids:
        sys.exit("[!] Detection Engine UUID를 찾을 수 없습니다.")
    if len(uuids) > 1:
        print(f"[*] 복수 DE 발견, 첫 번째 사용: {uuids[0]}")
    return uuids[0]


def list_policies(shell: FTDShell, de_uuid: str) -> dict:
    """단일 grep 명령으로 모든 Policy 이름·UUID 수집"""
    intrusion_dir = f"{DE_BASE}/{de_uuid}/intrusion"
    policies = {}
    raw = shell.run(f"grep '^# Name' {intrusion_dir}/snort.conf.* 2>/dev/null")
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        filepath, _, match_part = line.partition(':')
        parts = filepath.split("snort.conf.")
        if len(parts) < 2:
            continue
        policy_uuid = parts[1].split(".")[0]
        m = _RE_NAME.search(match_part)
        if m:
            name = m.group(1).strip()
            policies[name] = policy_uuid
            print(f"    발견: [{name}] → {policy_uuid}")
    return policies


def select_policy(policies: dict, requested: str) -> tuple:
    if not policies:
        sys.exit("[!] 배포된 Intrusion Policy를 찾을 수 없습니다.")
    req_lower = requested.lower()
    for name, uuid in policies.items():
        if name.lower() == req_lower:
            return name, uuid
    matches = [(n, u) for n, u in policies.items() if req_lower in n.lower()]
    if len(matches) == 1:
        return matches[0]
    elif len(matches) > 1:
        print(f"[!] 여러 정책 매칭: {[n for n, _ in matches]}")
        sys.exit("[!] --policy 인자를 더 구체적으로 지정하세요.")
    # 요청한 정책 없으면 "No Rules" 제외 첫 번째 자동 선택
    print(f"[!] '{requested}' 정책 없음. 자동 선택합니다.")
    for name, uuid in policies.items():
        if "no rules" not in name.lower():
            print(f"[*] 자동 선택: [{name}]")
            return name, uuid
    return list(policies.items())[0]


# ──────────────────────────────────────────────
# Local Rule 파일 탐색 및 파싱
# ──────────────────────────────────────────────
def extract_local_rules_from_policy(shell: FTDShell, de_uuid: str,
                                    policy_uuid: str) -> dict[int, dict]:
    """정책 디렉토리의 .rules 파일에서 Local SID(>= SID_MIN) 추출"""
    rule_dir = f"{DE_BASE}/{de_uuid}/intrusion/{policy_uuid}"
    out = shell.run(f"ls -1 {rule_dir}/*.rules 2>/dev/null")
    rule_files = [l.strip() for l in out.splitlines() if l.strip().endswith(".rules")]

    if not rule_files:
        print(f"    → {rule_dir} 에서 .rules 파일 없음")
        return {}

    print(f"    → {len(rule_files)}개 .rules 파일 탐색 중...")
    local: dict[int, dict] = {}
    for fpath in rule_files:
        content = shell.read_file(fpath)
        for line in content.splitlines():
            line = line.strip()
            if not _is_snort_rule(line):
                continue
            sid = _parse_sid(line)
            if sid is None or not (SID_MIN <= sid <= SID_MAX):
                continue
            if sid not in local:
                local[sid] = {
                    "GID": _parse_gid(line), "SID": sid,
                    "Message": _parse_msg(line), "rule": line,
                }
                _debug(f"  발견: SID={sid}")
    return local


def find_local_rules_fallback(shell: FTDShell) -> dict[int, dict]:
    """/ngfw 전체에서 local.rules 파일 탐색 (폴백)"""
    print("[*] 폴백: /ngfw 전체에서 local.rules 탐색 중...")
    out = shell.run("find /ngfw -name 'local.rules' 2>/dev/null", timeout=120)
    paths = [l.strip() for l in out.splitlines() if l.strip().startswith("/")]
    if not paths:
        print("    → local.rules 파일 없음")
        return {}

    local: dict[int, dict] = {}
    for fpath in paths:
        print(f"    발견: {fpath}")
        content = shell.read_file(fpath)
        for line in content.splitlines():
            line = line.strip()
            if not _is_snort_rule(line):
                continue
            sid = _parse_sid(line)
            if sid is None or not (SID_MIN <= sid <= SID_MAX):
                continue
            if sid not in local:
                local[sid] = {
                    "GID": _parse_gid(line), "SID": sid,
                    "Message": _parse_msg(line), "rule": line,
                }
    return local


# ──────────────────────────────────────────────
# CSV 저장
# ──────────────────────────────────────────────
def save_csv(rules: list[dict]) -> str:
    filename = f"fmc_snort2_local_rules_ssh_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    fpath = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(fpath, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=["GID", "SID", "Message", "rule"],
                                quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(sorted(rules, key=lambda r: r["SID"]))
    return fpath


# ──────────────────────────────────────────────
# 메인
# ──────────────────────────────────────────────
def main():
    global _DEBUG
    args   = parse_args()
    _DEBUG = args.debug

    print("=" * 60)
    print("  FTD Snort 2 Local Rule Extractor (SSH CLI 방식)")
    print(f"  FTD: {args.host}  |  SID 범위: {SID_MIN:,} ~ {SID_MAX:,}")
    print(f"  정책: {args.policy}")
    if _DEBUG:
        print("  *** 디버그 모드 ***")
    print("=" * 60 + "\n")

    ssh_pass  = FTD_PASS  or getpass.getpass(f"  SSH 비밀번호 ({args.user}@{args.host}): ")
    sudo_pass = SUDO_PASS or getpass.getpass("  sudo 비밀번호: ")

    shell = FTDShell(args.host, args.port, args.user, ssh_pass, sudo_pass)
    try:
        if not shell.setup():
            sys.exit("[!] 셸 초기화 실패")

        # Detection Engine UUID
        print("\n[*] Detection Engine 탐색...")
        de_uuid = find_de_uuid(shell)
        print(f"[+] DE UUID: {de_uuid}")

        # Policy UUID
        print("\n[*] Intrusion Policy 목록...")
        policies = list_policies(shell, de_uuid)
        policy_name, policy_uuid = select_policy(policies, args.policy)
        print(f"\n[+] 대상 정책: [{policy_name}]  ({policy_uuid})")

        # 정책 디렉토리에서 Local Rule 추출
        print("\n[*] 정책 디렉토리에서 Local Rule 탐색...")
        local_map = extract_local_rules_from_policy(shell, de_uuid, policy_uuid)

        # 없으면 폴백
        if not local_map:
            local_map = find_local_rules_fallback(shell)

        rules = list(local_map.values())
        print(f"\n[+] 총 추출 완료: {len(rules)}개 (SID 중복 제거 적용)")

    finally:
        shell.close()
        print("[*] SSH 연결 종료\n")

    if not rules:
        print("[!] 저장할 Local Rule이 없습니다.")
        if not _DEBUG:
            print("[팁] --debug 옵션으로 상세 로그를 확인하세요.")
        return

    fpath = save_csv(rules)
    sids  = [r["SID"] for r in rules]

    print("=" * 60)
    print("  추출 요약")
    print("=" * 60)
    print(f"  FTD            : {args.host}")
    print(f"  정책           : {policy_name}")
    print(f"  SID 검색 범위  : {SID_MIN:,} ~ {SID_MAX:,}")
    print(f"  추출된 Rule 수 : {len(rules)}개")
    print(f"  SID 범위       : {min(sids):,} ~ {max(sids):,}")
    print(f"  저장 파일      : {fpath}")
    print("=" * 60)


if __name__ == "__main__":
    main()
