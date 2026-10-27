// Standalone remote-control window (/rc/{sessionId}): full-screen desktop
// frame stream + keyboard injection. Transport: Type2 RCP relay by default;
// ⚡P2P negotiates a direct WebRTC data channel with the agent (signaled over
// Type1, PSK-bound auth, auto-fallback to relay) — docs/P2P_DESIGN.md.
import { useEffect, useRef, useState } from 'react';
import { useI18n } from './i18n';
import { useStore } from './store';

const api = (path: string, init?: RequestInit) =>
  fetch(path, {
    ...init,
    headers: { 'X-Wisp-Token': localStorage.getItem('wisp_token') ?? '', ...(init?.headers ?? {}) },
  });

type St = 'dialing' | 'connecting' | 'live' | 'closed' | 'error';

export default function RemoteControl({ sessionId }: { sessionId: string }) {
  const { t } = useI18n();
  const [status, setStatus] = useState<St>('dialing');
  const [err, setErr] = useState('');
  const [p2p, setP2p] = useState<'off' | 'neg' | 'live'>('off');
  const [fps, setFps] = useState(0);
  const imgRef = useRef<HTMLImageElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const pcRef = useRef<RTCPeerConnection | null>(null);
  const dcRef = useRef<RTCDataChannel | null>(null);
  const cnt = useRef(0);
  const lastUrl = useRef('');
  const openStreamRef = useRef<() => void>(() => {});

  const showFrame = (buf: ArrayBuffer) => {
    cnt.current++;
    const url = URL.createObjectURL(new Blob([buf], { type: 'image/png' }));
    if (lastUrl.current) URL.revokeObjectURL(lastUrl.current);
    lastUrl.current = url;
    if (imgRef.current) imgRef.current.src = url;
  };

  useEffect(() => {
    let dead = false;
    let ws: WebSocket | null = null;
    const tok = localStorage.getItem('wisp_token') ?? '';

    const openStream = () => {
      if (dead || p2pRef.current === 'live') return;
      setStatus('connecting');
      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      ws = new WebSocket(`${proto}://${location.host}/api/rcp/${encodeURIComponent(sessionId)}/channel?kind=view&token=${encodeURIComponent(tok)}`);
      ws.binaryType = 'arraybuffer';
      wsRef.current = ws;
      ws.onopen = () => !dead && setStatus('live');
      ws.onclose = () => !dead && p2pRef.current !== 'live' && setStatus('closed');
      ws.onmessage = (e) => showFrame(e.data as ArrayBuffer);
    };
    openStreamRef.current = openStream;

    const waitOnline = async () => {
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        if (dead) return;
        const st = await api(`/api/rcp/${sessionId}/status`).then((r) => r.json()).catch(() => ({ online: false }));
        if (st.online) { openStream(); return; }
      }
      if (!dead) { setStatus('error'); setErr(t('rcDialTimeout')); }
    };

    (async () => {
      const r = await api(`/api/rcp/${sessionId}/connect`, { method: 'POST' }).then((x) => x.json().then((d) => ({ ok: x.ok, d }))).catch(() => ({ ok: false, d: { error: 'api' } }));
      if (dead) return;
      if (!r.ok && r.d.status !== 'already-online') { setStatus('error'); setErr(r.d.error ?? 'connect failed'); return; }
      if (r.d.status === 'already-online') { openStream(); return; }
      void waitOnline();
    })();

    const bye = () => { void api(`/api/rcp/${sessionId}/disconnect`, { method: 'POST', keepalive: true }); };
    window.addEventListener('pagehide', bye);

    const t1 = setInterval(() => { setFps(cnt.current); cnt.current = 0; }, 1000);
    return () => {
      dead = true;
      clearInterval(t1);
      ws?.close();
      dcRef.current?.close();
      pcRef.current?.close();
      window.removeEventListener('pagehide', bye);
      void api(`/api/rcp/${sessionId}/disconnect`, { method: 'POST', keepalive: true });
      void api(`/api/p2p/${sessionId}/stop`, { method: 'POST', keepalive: true });
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  const p2pRef = useRef<'off' | 'neg' | 'live'>('off');

  const b64 = (s: string) => btoa(unescape(encodeURIComponent(s)));

  const fallback = (reason: string) => {
    if (p2pRef.current === 'off') return;
    p2pRef.current = 'off';
    setP2p('off');
    dcRef.current?.close(); dcRef.current = null;
    pcRef.current?.close(); pcRef.current = null;
    useStore.getState().toast({ kind: 'info', text: `↩ ${t('p2pFallback')} — ${reason}` });
    openStreamRef.current();
  };

  const startP2P = async () => {
    if (p2pRef.current !== 'off') { fallback(t('rcClose')); return; }
    p2pRef.current = 'neg'; setP2p('neg');
    try {
      const pc = new RTCPeerConnection({ iceServers: [] }); // host candidates only (no third-party STUN leak)
      pcRef.current = pc;
      const dc = pc.createDataChannel('rcp'); // reliable+ordered: chunk loss under unreliable mode was reassembling nothing; agent applies backpressure
      dc.binaryType = 'arraybuffer';
      dcRef.current = dc;
      let proof = '';
      let authed = false;
      const reasm = new Map<number, { total: number; have: number; parts: (Uint8Array | null)[] }>();
      const p2pFrame = (buf: ArrayBuffer) => {
        const dv = new DataView(buf);
        if (buf.byteLength < 13 || dv.getUint8(0) !== 1) { showFrame(buf); return; }
        const sq = dv.getUint32(1), idx = dv.getUint32(5), tot = dv.getUint32(9);
        if (reasm.size > 8) reasm.delete(reasm.keys().next().value as number);
        let r = reasm.get(sq);
        if (!r) { r = { total: tot, have: 0, parts: new Array(tot).fill(null) }; reasm.set(sq, r); }
        if (!r.parts[idx]) { r.parts[idx] = new Uint8Array(buf, 13); r.have++; }
        if (r.have === r.total) {
          let len = 0;
          for (const p of r.parts) len += (p as Uint8Array).length;
          const out = new Uint8Array(len);
          let off = 0;
          for (const p of r.parts) { out.set(p as Uint8Array, off); off += (p as Uint8Array).length; }
          reasm.delete(sq);
          showFrame(out.buffer as ArrayBuffer);
        }
      };
      dc.onmessage = (e) => {
        if (typeof e.data === 'string') {
          try {
            const m = JSON.parse(e.data);
            if (m.t === 'auth') {
              if (m.proof !== proof) { fallback(t('p2pProofFail')); return; }
              authed = true;
              dc.send(JSON.stringify({ t: 'auth-ok' }));
            }
          } catch { /* ignore */ }
          return;
        }
        if (authed) p2pFrame(e.data as ArrayBuffer);
      };
      dc.onopen = () => {
        if (p2pRef.current !== 'neg') return;
        p2pRef.current = 'live'; setP2p('live');
        setStatus('live');
        wsRef.current?.close(); // relay off: frames now direct
        useStore.getState().toast({ kind: 'ok', text: `⚡ ${t('p2pLive')}` });
      };
      pc.onconnectionstatechange = () => {
        if (pc.connectionState === 'failed' || pc.connectionState === 'closed') fallback(`ICE ${pc.connectionState}`);
      };
      await pc.setLocalDescription(await pc.createOffer());
      await Promise.race([
        new Promise<void>((res) => { const f = () => pc.iceGatheringState === 'complete' ? res() : setTimeout(f, 150); f(); }),
        new Promise<void>((res) => setTimeout(res, 3000)),
      ]);
      const r = await api(`/api/p2p/${sessionId}/bridge`, { method: 'POST', body: JSON.stringify({ offer: b64(pc.localDescription?.sdp ?? '') }) }).then((x) => x.json());
      if (!r.answer) { fallback(r.error ?? 'bridge failed'); return; }
      proof = r.proof ?? '';
      await pc.setRemoteDescription({ type: 'answer', sdp: decodeURIComponent(escape(atob(r.answer))) });
      setTimeout(() => { if (p2pRef.current === 'neg') fallback(t('p2pTimeout')); }, 12000);
    } catch (e) {
      fallback(String(e));
    }
  };

  const send = (obj: unknown) => {
    const dc = dcRef.current;
    if (p2pRef.current === 'live' && dc?.readyState === 'open') { dc.send(JSON.stringify(obj)); return; }
    if (wsRef.current?.readyState === WebSocket.OPEN) wsRef.current.send(JSON.stringify(obj));
  };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    e.preventDefault();
    const map: Record<string, string> = { Enter: 'enter', Tab: 'tab', Escape: 'esc', Backspace: 'backspace', ' ': 'space' };
    if (map[e.key]) send({ t: 'cmd', k: map[e.key] });
    else if (e.key.length === 1) send({ t: 'key', s: e.key });
  };

  const name = (t('rcTitle') || '').replace('{id}', sessionId.slice(0, 8));
  const stTxt = p2p === 'live' ? `● ${t('p2pLive')}` : p2p === 'neg' ? t('p2pNeg') : status === 'live' ? `● ${t('rcLive')}` : status === 'dialing' ? t('rcDialing') : status === 'connecting' ? t('rcConn') : status === 'error' ? `⚠ ${err}` : `○ ${t('rcClosed')}`;
  return (
    <div className="rc-root" tabIndex={0} onKeyDown={onKey} ref={(el) => el?.focus()}>
      <div className="rc-bar">
        <b>{name}</b>
        <span className={`rc-st ${status === 'live' || p2p === 'live' ? 'live' : status === 'error' ? 'closed' : 'connecting'}`}>{stTxt}</span>
        {(status === 'live' || p2p === 'live') && <span className="rc-fps">{fps} fps</span>}
        <span className="rc-hint">{t('rcHint')}</span>
        <button className={p2p !== 'off' ? 'p' : ''} title={t('p2pHint')} onClick={() => void startP2P()}>{p2p === 'off' ? '⚡ P2P' : p2p === 'neg' ? '⏳ P2P…' : '⚡ 直连'}</button>
        {status === 'error' && <button onClick={() => location.reload()}>↻ {t('retryWord')}</button>}
        <button onClick={() => document.documentElement.requestFullscreen?.()}>{t('rcFull')}</button>
        <button className="danger" onClick={() => window.close()}>{t('rcClose')}</button>
      </div>
      <div className="rc-stage">
        <img ref={imgRef} alt="" />
        {status !== 'live' && p2p !== 'live' && <div className="rc-overlay">{status === 'error' ? `⚠ ${err}` : status === 'dialing' ? t('rcDialing') : status === 'connecting' || p2p === 'neg' ? t('rcConn') : t('rcClosedHint')}</div>}
      </div>
    </div>
  );
}
