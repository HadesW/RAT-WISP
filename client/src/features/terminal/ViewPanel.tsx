import { useEffect, useRef, useState } from 'react';
import { tr } from '../../i18n';
import type { Session } from '../../types';
import { rcpURL, useRCPStatus } from './rcp';

const T = tr;

export default function ViewPanel({ session }: { session?: Session }) {
  const online = useRCPStatus(session?.id);
  const [frame, setFrame] = useState('');
  const [fps, setFps] = useState(0);
  const cnt = useRef(0);
  useEffect(() => {
    if (!session || online !== true) return;
    const ws = new WebSocket(rcpURL(session.id, 'view'));
    ws.binaryType = 'arraybuffer';
    let last = '';
    ws.onmessage = (e) => {
      cnt.current++;
      const blob = new Blob([e.data as ArrayBuffer], { type: 'image/png' });
      const url = URL.createObjectURL(blob);
      if (last) URL.revokeObjectURL(last);
      last = url; setFrame(url);
    };
    ws.onclose = () => setFrame('');
    const t = setInterval(() => { setFps(cnt.current); cnt.current = 0; }, 1000);
    return () => { clearInterval(t); URL.revokeObjectURL(last); ws.close(); };
  }, [session?.id, online]);

  if (!session) return <div className="console"><div className="c-out muted">{T('pickSessionWord')}</div></div>;
  if (online === false) return <div className="console"><div className="c-out muted">{T('t2Off')}</div></div>;
  return (
    <div className="view-host">
      {frame ? <img src={frame} alt="desktop" /> : <div className="c-out muted" style={{ padding: 16 }}>{T('viewWait')}</div>}
      <span className="view-fps">{fps > 0 ? `${fps} fps` : ''}</span>
    </div>
  );
}