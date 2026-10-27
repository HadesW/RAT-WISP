import { useEffect, useState } from 'react';
import { Api } from '../../api';

export function rcpURL(session: string, kind: string) {
  const tok = localStorage.getItem('wisp_token') ?? '';
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${proto}://${location.host}/api/rcp/${session}/channel?kind=${kind}&token=${encodeURIComponent(tok)}`;
}

export function useRCPStatus(session?: string) {
  const [online, setOnline] = useState<boolean | null>(null);
  useEffect(() => {
    let stop = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let fast = 0;
    if (!session) { setOnline(null); return; }
    // Poll fast while Type2 is down so a dial-in appears immediately; back off
    // after ~15s so a viewer left on an offline session does not keep hammering.
    const tick = async () => {
      let on = false;
      try {
        const r = await Api.rcp.status(session);
        on = !!r.online;
      } catch { /* transient: keep polling */ }
      if (stop) return;
      setOnline(on);
      if (on) fast = 0;
      timer = setTimeout(tick, on || fast++ > 15 ? 4000 : 1000);
    };
    void tick();
    return () => { stop = true; clearTimeout(timer); };
  }, [session]);
  return online;
}