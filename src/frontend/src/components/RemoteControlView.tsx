import { useEffect, useRef, useState } from 'react'
import { useT } from '../i18n'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

interface RCFrame {
  session_id: string
  seq: string
  w: string
  h: string
  data_url: string
}

// RemoteControlView is the dedicated window for the fast remote-control
// channel. Frames arrive as "rc:frame" events from the long-lived RCP
// connection (independent of the agent sleep interval). Input injection is OFF
// by default for safety and must be enabled explicitly.
export function RemoteControlView({ sessionId, standalone }: { sessionId: string; standalone?: boolean }) {
  const t = useT()
  const [imgSrc, setImgSrc] = useState<string | null>(null)
  const [info, setInfo] = useState({ w: 0, h: 0, seq: 0 })
  const [fps, setFps] = useState(0)
  const [status, setStatus] = useState<'connecting' | 'live' | 'stopped'>('connecting')
  const [interact, setInteract] = useState(false)
  const [proto, setProto] = useState('kcp')
  const [streamError, setStreamError] = useState<string | null>(null)
  const boxRef = useRef<HTMLDivElement>(null)
  const lastMoveRef = useRef(0)
  const frameTimesRef = useRef<number[]>([])
  const fpsTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Open the channel over the selected transport (tcp or kcp).
  const openChannel = (p: string) => {
    setStatus('connecting')
    callBackend('github.com/user/wisp/services.SessionService.RemoteControlOpen', sessionId, p).catch(() => {
      /* ignore */
    })
  }

  // Start the channel when the window opens
  useEffect(() => {
    openChannel(proto)
    fpsTimerRef.current = setInterval(() => {
      const now = Date.now()
      const recent = frameTimesRef.current.filter(t => now - t < 1000)
      frameTimesRef.current = recent
      setFps(recent.length)
    }, 500)
    return () => {
      if (fpsTimerRef.current) clearInterval(fpsTimerRef.current)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // Switching transport re-opens the channel with the new protocol.
  const onProtoChange = (p: string) => {
    if (p === proto) return
    setProto(p)
    callBackend('github.com/user/wisp/services.SessionService.RemoteControlClose', sessionId)
      .finally(() => openChannel(p))
  }

  // Subscribe to frames; the subscription is removed when the window closes so
  // the callbacks do not accumulate across repeated opens.
  useEffect(() => {
    let off: (() => void) | null = null
    let cancelled = false
    const init = async () => {
      const runtime = await import('@wailsio/runtime')
      off = runtime.Events.On('rc:frame', (event: { data: RCFrame | RCFrame[] }) => {
        if (cancelled) return
        // Wails delivers single-arg Emit payloads directly (not as arrays)
        const frame = Array.isArray(event.data) ? event.data[0] : event.data
        if (!frame || frame.session_id !== sessionId) return
        setImgSrc(frame.data_url)
        setInfo({ w: Number(frame.w) || 0, h: Number(frame.h) || 0, seq: Number(frame.seq) || 0 })
        frameTimesRef.current.push(Date.now())
        if (frameTimesRef.current.length > 120) frameTimesRef.current = frameTimesRef.current.slice(-60)
        setStatus('live')
        setStreamError(null)
      })
      runtime.Events.On('rc:error', (event: { data: { session_id?: string; error?: string } | Array<{ session_id?: string; error?: string }> }) => {
        if (cancelled) return
        const msg = Array.isArray(event.data) ? event.data[0] : event.data
        if (!msg || msg.session_id !== sessionId) return
        setStreamError(msg.error || 'stream error')
        setStatus('stopped')
      })
    }
    init()
    return () => {
      cancelled = true
      if (off) off()
    }
  }, [sessionId])

  // Stop the channel when a standalone window is closed
  useEffect(() => {
    if (!standalone) return
    const stopOnClose = () => {
      callBackend('github.com/user/wisp/services.SessionService.RemoteControlClose', sessionId)
    }
    window.addEventListener('beforeunload', stopOnClose)
    return () => {
      window.removeEventListener('beforeunload', stopOnClose)
      stopOnClose()
    }
  }, [sessionId, standalone])

  const stop = async () => {
    setStatus('stopped')
    try {
      await callBackend('github.com/user/wisp/services.SessionService.RemoteControlClose', sessionId)
    } catch { /* ignore */ }
  }

  const restart = async () => {
    openChannel(proto)
  }

  const sendInput = (type: string, extra: Record<string, unknown> = {}) => {
    if (status === 'stopped' || !interact) return
    callBackend('github.com/user/wisp/services.SessionService.RemoteControlInput', sessionId, JSON.stringify({ type, ...extra }))
  }

  const toggleInteract = () => {
    setInteract(v => {
      const next = !v
      if (next) setTimeout(() => boxRef.current?.focus(), 0)
      return next
    })
  }

  const toScreen = (e: React.MouseEvent): { x: number; y: number } => {
    const el = boxRef.current
    if (!el) return { x: 0, y: 0 }
    const rect = el.getBoundingClientRect()
    const sx = info.w > 0 ? info.w / rect.width : 1
    const sy = info.h > 0 ? info.h / rect.height : 1
    return {
      x: Math.round((e.clientX - rect.left) * sx),
      y: Math.round((e.clientY - rect.top) * sy),
    }
  }

  const onMouseDown = (e: React.MouseEvent) => {
    const { x, y } = toScreen(e)
    sendInput('click', { x, y, button: e.button === 2 ? 'right' : 'left', down: true })
  }
  const onMouseUp = (e: React.MouseEvent) => {
    const { x, y } = toScreen(e)
    sendInput('click', { x, y, button: e.button === 2 ? 'right' : 'left', down: false })
  }
  const onMouseMove = (e: React.MouseEvent) => {
    const now = Date.now()
    if (now - lastMoveRef.current < 50) return
    lastMoveRef.current = now
    const { x, y } = toScreen(e)
    sendInput('move', { x, y })
  }
  const onKey = (e: React.KeyboardEvent, down: boolean) => {
    if (e.key === 'Tab') e.preventDefault()
    const code = e.keyCode || e.which
    if (code) sendInput('key', { code, down })
  }

  const statusText =
    status === 'live'
      ? `${t('rcLive')} · ${info.w}×${info.h} · ${fps} ${t('rcFps')} · ${t('rcSeq')} ${info.seq}`
      : status === 'stopped'
        ? t('rcStopped')
        : t('rcConnecting')

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: '#141419' }}>
      <div className="stream-header" onClick={e => e.stopPropagation()}>
        <span className="stream-session-chip">
          <span className={`stream-session-dot ${status}`} />
          <span className="stream-session-id mono">{sessionId}</span>
        </span>
        {status === 'live' ? (
          <span className="stream-metrics">
            <span className="stream-metric">{info.w}×{info.h}</span>
            <span className="stream-metric">{fps} {t('rcFps')}</span>
            <span className="stream-metric">{t('rcSeq')} {info.seq}</span>
          </span>
        ) : (
          <span className={`stream-state ${status}`}>{statusText}</span>
        )}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          <label className="stream-proto">
            <span>{t('rcProto')}</span>
            <select value={proto} onChange={e => onProtoChange(e.target.value)}>
              <option value="tcp">TCP</option>
              <option value="kcp">KCP</option>
            </select>
          </label>
          <button
            className={`toolbar-btn${interact ? ' primary' : ''}`}
            onClick={toggleInteract}
            title="When enabled, mouse and keyboard events are injected on the target"
          >
            {interact ? t('rdpInputOn') : t('rdpInputOff')}
          </button>
          {status === 'stopped' ? (
            <button className="toolbar-btn" onClick={restart}>{t('rcRestart')}</button>
          ) : (
            <button className="toolbar-btn" onClick={stop}>{t('rcStop')}</button>
          )}
        </span>
      </div>
      <div
        ref={boxRef}
        tabIndex={0}
        className="rdp-viewport"
        onMouseDown={onMouseDown}
        onMouseUp={onMouseUp}
        onMouseMove={onMouseMove}
        onContextMenu={e => e.preventDefault()}
        onKeyDown={e => onKey(e, true)}
        onKeyUp={e => onKey(e, false)}
      >
        {imgSrc ? (
          <img src={imgSrc} alt="remote control" className="rdp-frame" draggable={false} />
        ) : (
          <div className="rdp-placeholder">
            <div className={`rdp-placeholder-dot ${status === 'stopped' ? 'off' : 'pulse'}`} />
            <div className="rdp-placeholder-title">
              {status === 'stopped' ? t('rcStopped') : t('rcConnecting')}
            </div>
            <div className="rdp-placeholder-sub">
              Session <span className="mono">{sessionId}</span>
            </div>
            {streamError ? (
              <div className="rdp-placeholder-err mono">{streamError}</div>
            ) : (
              <div className="rdp-placeholder-hint">
                {status === 'stopped'
                  ? t('rcStoppedHint')
                  : t('rcFastHint')}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
