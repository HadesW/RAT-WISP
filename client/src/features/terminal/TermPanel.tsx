import { useEffect, useRef, useState } from 'react';
import type { Terminal } from '@xterm/xterm';
import type { FitAddon } from '@xterm/addon-fit';
import { useI18n, tr } from '../../i18n';
import { Api } from '../../api';
import type { Session } from '../../types';
import { rcpURL, useRCPStatus } from './rcp';

const T = tr;

type ShellCap = { tty: boolean; shell: string; os: string; encoding: string };

// Physical scan codes for the win32-input-mode key records ConPTY expects.
// Plain bytes are fine for printable keys, but a raw 0x03 never becomes a
// console control event, so Ctrl+<letter> is sent as a key chord instead.
const WIN32_SCAN: Record<string, number> = {
  KeyA: 0x1e, KeyB: 0x30, KeyC: 0x2e, KeyD: 0x20, KeyE: 0x12, KeyF: 0x21,
  KeyG: 0x22, KeyH: 0x23, KeyI: 0x17, KeyJ: 0x24, KeyK: 0x25, KeyL: 0x26,
  KeyM: 0x32, KeyN: 0x31, KeyO: 0x18, KeyP: 0x19, KeyQ: 0x10, KeyR: 0x13,
  KeyS: 0x1f, KeyT: 0x14, KeyU: 0x16, KeyV: 0x2f, KeyW: 0x11, KeyX: 0x2d,
  KeyY: 0x15, KeyZ: 0x2c,
};

function win32CtrlChord(code: string): string | null {
  const m = /^Key([A-Z])$/.exec(code);
  const sc = WIN32_SCAN[code];
  if (!m || sc == null) return null;
  const vk = m[1].charCodeAt(0);
  const uc = vk - 64;
  return `\x1b[17;29;0;1;8;1_\x1b[${vk};${sc};${uc};1;8;1_`
    + `\x1b[${vk};${sc};${uc};0;8;1_\x1b[17;29;0;0;0;1_`;
}

export default function TermPanel({ session }: { session?: Session }) {
  const { t } = useI18n();
  const online = useRCPStatus(session?.id);
  const host = useRef<HTMLDivElement>(null);
  const [dial, setDial] = useState<'idle' | 'dialing' | 'waiting' | 'failed'>('idle');
  const [dialErr, setDialErr] = useState('');
  const [retry, setRetry] = useState(0);
  const [cap, setCap] = useState<ShellCap | null>(null);
  const [fontSize, setFontSize] = useState(12);
  const capRef = useRef<ShellCap | null>(null);
  const live = useRef<{ ws?: WebSocket; term?: Terminal; fit?: FitAddon; ro?: ResizeObserver; data?: { dispose: () => void } }>({});

  // Opening the shell is itself the intent to use Type2 — dial it right away
  // instead of asking the operator to press a second "connect" button.
  useEffect(() => {
    if (!session || online !== false) { setDial('idle'); setDialErr(''); return; }
    let stop = false;
    setDial('dialing');
    setDialErr('');
    Api.rcp.connect(session.id)
      .then(() => { if (!stop) setDial('waiting'); })
      .catch((e) => {
        if (stop) return;
        setDial('failed');
        setDialErr(e instanceof Error ? e.message : String(e));
      });
    return () => { stop = true; };
  }, [session?.id, online, retry]);

  useEffect(() => {
    if (!session || online !== true || !host.current) return;
    let disposed = false;
    capRef.current = null;
    setCap(null);
    const closeLive = () => {
      const l = live.current;
      live.current = {};
      if (l.data) l.data.dispose();
      if (l.ro) l.ro.disconnect();
      if (l.ws) { try { l.ws.close(); } catch { /* ignore */ } }
      if (l.term) l.term.dispose();
    };
    void (async () => {
      const { Terminal } = await import('@xterm/xterm');
      const { FitAddon } = await import('@xterm/addon-fit');
      if (disposed || !host.current) return;
      host.current.innerHTML = '';
      const term = new Terminal({
        fontSize: 12,
        cursorBlink: true,
        convertEol: true, // pipe fallback only; disabled when the agent reports a tty
        scrollback: 5000,
        fontFamily: '"Cascadia Mono", Consolas, "Microsoft YaHei Mono", "Noto Sans Mono CJK SC", monospace',
        theme: {
          background: '#0c0c0e', foreground: '#d6d6dd', cursor: '#7aa2f7',
          selectionBackground: 'rgba(122,162,247,.28)',
        },
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(host.current);
      // The bottom dock settles one frame after the tab switch; an immediate
      // fit can pick one extra row and paint it under the status bar.
      const refit = () => {
        if (disposed) return;
        try { fit.fit(); } catch { /* zero-size while hidden */ }
      };
      refit();
      requestAnimationFrame(refit);
      window.setTimeout(refit, 60);
      window.setTimeout(refit, 220);
      if (document.fonts?.ready) void document.fonts.ready.then(refit).catch(() => {});
      const ws = new WebSocket(rcpURL(session.id, 'shell'));
      const dec = new TextDecoder();
      const enc = new TextEncoder();
      ws.binaryType = 'arraybuffer';
      const sendBin = (s: string) => { if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(s)); };
      const sendResize = () => {
        if (ws.readyState !== WebSocket.OPEN) return;
        try { ws.send(JSON.stringify({ op: 'resize', cols: term.cols, rows: term.rows })); } catch { /* closed */ }
      };
      ws.onopen = () => term.focus();
      ws.onmessage = (e) => {
        // JSON control rides as WebSocket text; terminal bytes stay binary.
        if (typeof e.data === 'string') {
          try {
            const m = JSON.parse(e.data) as Partial<ShellCap> & { op?: string };
            if (m.op === 'hello') {
              const c: ShellCap = {
                tty: !!m.tty,
                shell: m.shell || 'shell',
                os: m.os || session.info.os,
                encoding: m.encoding || 'utf-8',
              };
              capRef.current = c;
              setCap(c);
              term.options.convertEol = !c.tty;
              if (c.tty) sendResize();
            }
          } catch { /* not control */ }
          return;
        }
        try { term.write(dec.decode(new Uint8Array(e.data as ArrayBuffer), { stream: true })); } catch { /* disposed */ }
      };
      ws.onclose = () => { try { term.write(`\r\n\x1b[2m${T('t2Gone')}\x1b[0m\r\n`); } catch { /* disposed */ } };
      term.attachCustomKeyEventHandler((ev) => {
        if (ev.type !== 'keydown') return true;
        const mod = ev.ctrlKey || ev.metaKey;
        if (mod && ev.shiftKey && ev.code === 'KeyC') {
          const s = term.getSelection();
          if (s) { void navigator.clipboard.writeText(s); term.clearSelection(); return false; }
        }
        if (mod && ev.shiftKey && ev.code === 'KeyV') {
          void navigator.clipboard.readText().then((txt) => { if (txt) term.paste(txt); }).catch(() => {});
          return false;
        }
        const cap = capRef.current;
        if (cap?.tty && cap.os === 'windows' && ev.ctrlKey && !ev.shiftKey && !ev.altKey && !ev.metaKey) {
          const chord = win32CtrlChord(ev.code);
          if (chord) {
            ev.preventDefault();
            sendBin(chord);
            return false;
          }
        }
        return true;
      });
      // Line mode is only for legacy pipe agents: no remote echo, no line
      // discipline, no Ctrl+C. PTY agents get raw keystrokes untouched.
      const nl = session.info.os === 'windows' ? '\r\n' : '\n';
      let line = '';
      const erase = (n: number) => { for (let i = 0; i < n; i++) term.write('\b \b'); };
      const sendLine = () => { sendBin(line + nl); term.write('\r\n'); line = ''; };
      const dataDisp = term.onData((d) => {
        if (ws.readyState !== WebSocket.OPEN) return;
        if (capRef.current?.tty) { sendBin(d); return; }
        if (d.startsWith('\x1b')) return;
        for (const ch of d) {
          if (ch === '\r' || ch === '\n') sendLine();
          else if (ch === '\x7f') { if (line) { line = Array.from(line).slice(0, -1).join(''); erase(1); } }
          else if (ch === '\x15') { if (line) { erase(Array.from(line).length); line = ''; } }
          else if (ch === '\x03') {
            // no console behind the pipe: 0x03 cannot act as a signal, so only
            // drop what is still buffered here and never send it
            if (line) { erase(Array.from(line).length); line = ''; }
            term.write('^C\r\n');
          } else if (ch >= ' ') { line += ch; term.write(ch); }
        }
      });
      let last = { c: term.cols, r: term.rows };
      const ro = new ResizeObserver(() => {
        try { fit.fit(); } catch { /* hidden */ }
        if (term.cols === last.c && term.rows === last.r) return;
        last = { c: term.cols, r: term.rows };
        if (capRef.current?.tty) sendResize();
      });
      ro.observe(host.current);
      live.current = { ws, term, fit, ro, data: dataDisp };
      if (disposed) closeLive();
    })();
    return () => { disposed = true; closeLive(); };
  }, [session?.id, online]);

  useEffect(() => {
    const l = live.current;
    if (!l.term) return;
    l.term.options.fontSize = fontSize;
    try { l.fit?.fit(); } catch { /* hidden */ }
  }, [fontSize]);

  if (!session) return <div className="console"><div className="c-out muted">{T('pickSessionWord')}</div></div>;
  if (online === false) return (
    <div className="console">
      <div className="c-out muted">{T('t2Wait')}</div>
      <div style={{ padding: 10 }}>
        {dial === 'failed'
          ? <>
              <span className="c-err">⚠ {dialErr || T('t2Off')}</span>{' '}
              <button className="p" onClick={() => setRetry((n) => n + 1)}>🔌 {T('retryWord')}</button>
            </>
          : <span className="muted">🔌 {dial === 'dialing' ? T('rcDialing') : T('t2Check')}</span>}
      </div>
    </div>
  );
  if (online === null) return <div className="console"><div className="c-out muted">{T('t2Check')}</div></div>;
  return (
    <div className="term-wrap">
      <div className="term-bar">
        <span className="term-chip">🐚 {cap?.shell ?? '…'}</span>
        <span className={`term-chip ${cap ? (cap.tty ? 'ok' : 'warn') : ''}`}>
          {cap ? (cap.tty ? `tty · ${cap.encoding}` : `pipe · ${t('termLineMode')}`) : t('termWait')}
        </span>
        {cap && !cap.tty && <span title={t('termPipeHint')} style={{ cursor: 'help' }}>ⓘ</span>}
        <span style={{ flex: 1 }} />
        <button onClick={() => { const s = live.current.term?.getSelection(); if (s) void navigator.clipboard.writeText(s); }} title={t('termCopy')}>⧉</button>
        <button onClick={() => void navigator.clipboard.readText().then((txt) => { if (txt) live.current.term?.paste(txt); }).catch(() => {})} title={t('termPaste')}>📋</button>
        <button onClick={() => live.current.term?.clear()} title={t('termClear')}>⌧</button>
        <button onClick={() => setFontSize((n) => Math.max(10, n - 1))}>A−</button>
        <button onClick={() => setFontSize((n) => Math.min(20, n + 1))}>A+</button>
      </div>
      <div className="term-host" ref={host}
        onContextMenu={(e) => {
          e.preventDefault();
          const term = live.current.term;
          if (!term) return;
          const s = term.getSelection();
          if (s) { void navigator.clipboard.writeText(s); term.clearSelection(); }
          else void navigator.clipboard.readText().then((txt) => { if (txt) term.paste(txt); }).catch(() => {});
        }} />
    </div>
  );
}