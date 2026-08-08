import { useEffect, useRef, useState } from 'react'
import { useT } from '../i18n'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

interface RdpFrame {
  seq: number
  w: number
  h: number
  data: string // base64 JPEG
}

// RemoteDesktopView renders a live screen stream from a Windows agent. Frames
// arrive as "rdp:frame" events (one per checkin) and are shown in a canvas-like
// area; mouse / keyboard events are forwarded to the agent as input tasks.
export function RemoteDesktopView({ sessionId, standalone }: { sessionId: string; standalone?: boolean }) {
  const t = useT()
  const [imgSrc, setImgSrc] = useState<string | null>(null)
  const [info, setInfo] = useState({ w: 0, h: 0, seq: 0, lastSeen: '', started: false })
  const [stopped, setStopped] = useState(false)
  // Input injection is OFF by default so accidental clicks/keys never touch
  // the target machine; the operator enables it explicitly.
  const [interact, setInteract] = useState(false)
  const boxRef = useRef<HTMLDivElement>(null)
  const lastMoveRef = useRef(0)
  const startedRef = useRef(false)

  // Start the stream when the view opens
  useEffect(() => {
    callBackend('github.com/user/wisp/services.SessionService.RemoteDesktopStart', sessionId, 500, 50, 15)
      .then(() => { startedRef.current = true })
      .catch(() => { /* ignore */ })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // In a standalone window, stop the agent stream when the window is closed
  useEffect(() => {
    if (!standalone) return
    const stopOnClose = () => {
      callBackend('github.com/user/wisp/services.SessionService.RemoteDesktopStop', sessionId)
    }
    window.addEventListener('beforeunload', stopOnClose)
    return () => {
      window.removeEventListener('beforeunload', stopOnClose)
      stopOnClose()
    }
  }, [sessionId, standalone])

  // Subscribe to frames; the subscription is removed when the window closes so
  // the callbacks do not accumulate across repeated opens.
  useEffect(() => {
    let off: (() => void) | null = null
    let cancelled = false
    const init = async () => {
      const runtime = await import('@wailsio/runtime')
      off = runtime.Events.On('rdp:frame', (event: { data: { session_id: string; frame: string } | Array<{ session_id: string; frame: string }> }) => {
        if (cancelled) return
        // Wails delivers the emitted value directly (single-arg Emit); it is
        // the object itself, not an array. Handle both shapes defensively.
        const payload = Array.isArray(event.data) ? event.data[0] : event.data
        if (!payload || payload.session_id !== sessionId) return
        try {
          const frame: RdpFrame = JSON.parse(payload.frame)
          setImgSrc(`data:image/jpeg;base64,${frame.data}`)
          setInfo({ w: frame.w, h: frame.h, seq: frame.seq, lastSeen: new Date().toLocaleTimeString(), started: true })
        } catch { /* ignore */ }
      })
    }
    init()
    return () => {
      cancelled = true
      if (off) off()
    }
  }, [sessionId])

  const stop = async () => {
    setStopped(true)
    try {
      await callBackend('github.com/user/wisp/services.SessionService.RemoteDesktopStop', sessionId)
    } catch { /* ignore */ }
  }

  const restart = async () => {
    setStopped(false)
    try {
      await callBackend('github.com/user/wisp/services.SessionService.RemoteDesktopStart', sessionId, 500, 50, 15)
    } catch { /* ignore */ }
  }

  const sendInput = (type: string, extra: Record<string, unknown> = {}) => {
    if (stopped || !interact) return
    callBackend('github.com/user/wisp/services.SessionService.RemoteDesktopInput', sessionId, JSON.stringify({ type, ...extra }))
  }

  const toggleInteract = () => {
    setInteract(v => {
      const next = !v
      if (next) setTimeout(() => boxRef.current?.focus(), 0)
      return next
    })
  }

  // Map a pointer event to target screen coordinates (account for CSS scaling)
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
    if (now - lastMoveRef.current < 80) return
    lastMoveRef.current = now
    const { x, y } = toScreen(e)
    sendInput('move', { x, y })
  }

  const onKey = (e: React.KeyboardEvent, down: boolean) => {
    if (e.key === 'Tab') e.preventDefault()
    const code = e.keyCode || e.which
    if (code) sendInput('key', { code, down })
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: '#0d0d0d' }}>
      <div className="stream-header" onClick={e => e.stopPropagation()}>
        <span className="stream-session-chip">
          <span className={`stream-session-dot ${stopped ? 'stopped' : info.started ? 'live' : 'connecting'}`} />
          <span className="stream-session-id mono">{sessionId}</span>
        </span>
        {info.started && !stopped && (
          <span className="stream-metrics">
            <span className="stream-metric">{info.w}×{info.h}</span>
            <span className="stream-metric">seq {info.seq}</span>
            <span className="stream-metric">{info.lastSeen}</span>
          </span>
        )}
        {!info.started && !stopped && <span className="stream-state connecting">{t('rdpWaiting')}</span>}
        {stopped && <span className="stream-state stopped">{t('rdpStopped')}</span>}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          <button
            className={`toolbar-btn${interact ? ' primary' : ''}`}
            onClick={toggleInteract}
            title="When enabled, mouse and keyboard events are injected on the target"
          >
            {interact ? t('rdpInputOn') : t('rdpInputOff')}
          </button>
          {stopped && (
            <button className="toolbar-btn" onClick={restart}>{t('rdpRestart')}</button>
          )}
          {!stopped && (
            <button className="toolbar-btn" onClick={stop}>{t('rdpStop')}</button>
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
          <img src={imgSrc} alt="remote desktop" className="rdp-frame" draggable={false} />
        ) : (
          <div className="rdp-placeholder">
            <div className={`rdp-placeholder-dot ${stopped ? 'off' : 'pulse'}`} />
            <div className="rdp-placeholder-title">
              {stopped ? t('rdpStopped') : t('rdpWaiting')}
            </div>
            <div className="rdp-placeholder-sub">
              Session <span className="mono">{sessionId}</span>
            </div>
            <div className="rdp-placeholder-hint">
              {stopped
                ? t('rdpStreamStopped')
                : t('rdpVerifyHint')}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
