#!/usr/bin/env python3
"""Control the driver-lab test VM (raw TCP command channel).

The VM listener accepts line commands (cmd/cd/upload/b64put/download/sha256/
info/caps/prompt/exit) and runs everything else through cmd.exe. This client
keeps the interactive prompt on so command completion is detectable, and adds
binary-safe upload plus base64 text download.

Usage:
  python scripts/vmctl.py info
  python scripts/vmctl.py run "hostname"
  python scripts/vmctl.py upload agent/agent-rs/target/release/wisp-agent-rs.exe C:\\drv\\wisp-agent-rs.exe
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import socket
import sys
import time

DEFAULT_HOST = os.environ.get("WISP_VM_HOST", "192.168.32.136")
DEFAULT_PORT = int(os.environ.get("WISP_VM_PORT", "4444"))
PROMPT = re.compile(rb"(?m)^[A-Za-z]:\\[^>\r\n]*>\s*$")


def _decode(data: bytes) -> str:
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


class VMError(RuntimeError):
    pass


class VM:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 30.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock: socket.socket | None = None

    def __enter__(self) -> "VM":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), 10)
        self.sock.settimeout(2.0)
        self._read_until_prompt(timeout=10)

    def close(self) -> None:
        if not self.sock:
            return
        try:
            self.sock.sendall(b"exit\n")
        except OSError:
            pass
        self.sock.close()
        self.sock = None

    def _recv(self, timeout: float) -> bytes:
        deadline = time.time() + timeout
        buf = b""
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                if buf and PROMPT.search(buf):
                    return buf
                continue
            if not chunk:
                return buf
            buf += chunk
            if PROMPT.search(buf):
                return buf
        return buf

    def _read_until_prompt(self, timeout: float = 30) -> str:
        data = self._recv(timeout)
        if not PROMPT.search(data):
            raise VMError(f"prompt timeout, got: {_decode(data[-400:])!r}")
        return _decode(data)

    def raw(self, line: str) -> None:
        self.sock.sendall(line.encode() + b"\n")

    def run(self, command: str, timeout: float = 60) -> str:
        """Run one cmd.exe command and return its full transcript."""
        # driver-lab executes unknown lines with cmd.exe /c; prepend 'cmd ' is
        # unnecessary and changes quoting, so send the command verbatim.
        self.raw(command)
        return self._read_until_prompt(timeout)

    def info(self) -> dict[str, str]:
        out = self.run("info")
        info = {}
        for line in out.splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                info[k.strip()] = v.strip()
        return info

    def _wait_for(self, needle: str, timeout: float = 30) -> str:
        deadline = time.time() + timeout
        buf = b""
        while time.time() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            if needle.encode() in buf:
                # consume the trailing prompt after READY as well
                time.sleep(0.1)
                try:
                    buf += self.sock.recv(65536)
                except (socket.timeout, OSError):
                    pass
                return _decode(buf)
        raise VMError(f"timeout waiting for {needle!r}: {_decode(buf[-400:])!r}")

    def upload(self, local_path: str, remote_path: str) -> str:
        size = os.path.getsize(local_path)
        self.raw(f"upload {remote_path} {size}")
        self._wait_for("READY")
        with open(local_path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                self.sock.sendall(chunk)
        return self._read_until_prompt(timeout=120)

    def b64put(self, local_path: str, remote_path: str) -> str:
        self.raw(f"b64put {remote_path}")
        self._wait_for("READY")
        with open(local_path, "rb") as f:
            data = f.read()
        enc = base64.b64encode(data).decode()
        for i in range(0, len(enc), 76):
            self.sock.sendall(enc[i : i + 76].encode() + b"\n")
        self.raw("EOF")
        return self._read_until_prompt(timeout=120)

    def put_text(self, remote_path: str, text: str) -> str:
        tmp = remote_path + ".put"
        with open(tmp, "wb") as f:
            f.write(text.encode())
        try:
            return self.upload(tmp, remote_path)
        finally:
            os.unlink(tmp)

    def download(self, remote_path: str, local_path: str) -> int:
        out = self.run(f"download {remote_path}", timeout=120)
        start = out.find("BEGIN")
        end = out.find("END", start)
        if start < 0 or end < 0:
            raise VMError(f"no BEGIN/END markers: {out[-500:]!r}")
        b64 = "".join(
            line.strip()
            for line in out[start:end].splitlines()[1:]
            if line.strip() and not line.startswith("BEGIN")
        )
        data = base64.b64decode(b64)
        with open(local_path, "wb") as f:
            f.write(data)
        return len(data)

    def sha256(self, remote_path: str) -> str:
        out = self.run(f"sha256 {remote_path}")
        m = re.search(r"\b([0-9a-fA-F]{64})\b", out)
        return m.group(1).lower() if m else ""

    def exists(self, remote_path: str) -> bool:
        out = self.run(f'if exist "{remote_path}" (echo YES) else (echo NO)')
        return "YES" in out

    def kill(self, image_name: str) -> str:
        return self.run(f"taskkill /F /IM {image_name}", timeout=20)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["info", "run", "upload", "put", "download", "sha256", "exists", "kill"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", default=DEFAULT_PORT, type=int)
    a = ap.parse_args()

    with VM(a.host, a.port) as vm:
        if a.action == "info":
            for k, v in vm.info().items():
                print(f"{k}: {v}")
        elif a.action == "run":
            print(vm.run(" ".join(a.args)))
        elif a.action == "upload":
            print(vm.upload(a.args[0], a.args[1]))
        elif a.action == "put":
            # put <local-text-file> <remote>: UTF-8 text, no binary re-encode
            with open(a.args[0], "r", encoding="utf-8") as f:
                print(vm.put_text(a.args[1], f.read()))
        elif a.action == "download":
            print(f"{vm.download(a.args[0], a.args[1])} bytes")
        elif a.action == "sha256":
            print(vm.sha256(a.args[0]))
        elif a.action == "exists":
            print("yes" if vm.exists(a.args[0]) else "no")
        elif a.action == "kill":
            print(vm.kill(a.args[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
