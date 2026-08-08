import { useCallback, useEffect, useRef, useState } from 'react'
import { useT } from '../i18n'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

interface ScreenshotResult {
  status: string // pending | completed | failed
  path: string
  w: number
  h: number
  data_url: string
}

// ScreenshotView captures and previews a single screenshot of a session in a
// standalone window.
export function ScreenshotView({ sessionId }: { sessionId: string }) {
  const t = useT()
  const [res, setRes] = useState<ScreenshotResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const startedRef = useRef(false)

  const pollTask = async (taskID: string, timeoutMs = 30000) => {
    const start = Date.now()
    while (Date.now() - start < timeoutMs) {
      const task = await callBackend('github.com/user/wisp/services.SessionService.GetTask', taskID)
      if (task && task.status !== 'pending' && task.status !== 'sent') return task
      await new Promise(r => setTimeout(r, 400))
    }
    return null
  }

  const capture = useCallback(async () => {
    setBusy(true)
    setNotice(null)
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.TakeScreenshot', sessionId)
      const task = await pollTask(taskID)
      if (!task) {
        setNotice({ kind: 'err', text: t('shotTimedOut') })
        return
      }
      const r = await callBackend('github.com/user/wisp/services.SessionService.GetScreenshot', taskID) as ScreenshotResult
      if (r?.status === 'completed') {
        setRes(r)
      } else {
        setNotice({ kind: 'err', text: (r?.path || r?.status || '') })
      }
    } catch (e) {
      setNotice({ kind: 'err', text: String(e) })
    } finally {
      setBusy(false)
    }
  }, [sessionId, t])

  // Capture exactly once on mount. useT() returns a fresh function every render,
  // which would otherwise make this effect re-run (and re-capture) on every
  // state update; a ref guard keeps it a single screenshot until the button is
  // pressed.
  useEffect(() => {
    if (startedRef.current) return
    startedRef.current = true
    capture()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setNotice({ kind: 'ok', text: t('fsCopyDone') + ': ' + text })
    } catch { /* ignore */ }
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', background: '#141419' }}>
      <div className="stream-header" onClick={e => e.stopPropagation()}>
        <span className="stream-session-chip">
          <span className="stream-session-dot" style={{ background: busy ? 'var(--info)' : 'var(--ok)' }} />
          <span className="stream-session-id mono">{sessionId}</span>
        </span>
        {res && <span className="stream-metrics">
          <span className="stream-metric">{res.w}×{res.h}</span>
          <span className="stream-metric" title={res.path} onClick={() => copy(res.path)} style={{ cursor: 'pointer' }}>{res.path}</span>
        </span>}
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center' }}>
          <button className="toolbar-btn primary" onClick={capture} disabled={busy}>
            {busy ? t('shotCapturing') : t('shotRetake')}
          </button>
        </span>
      </div>
      <div className="rdp-viewport">
        {res?.data_url ? (
          <img src={res.data_url} alt="screenshot" className="rdp-frame" draggable={false} />
        ) : (
          <div className="rdp-placeholder">
            <div className={`rdp-placeholder-dot ${busy ? 'pulse' : 'off'}`} />
            <div className="rdp-placeholder-title">{busy ? t('shotCapturing') : t('shotEmpty')}</div>
            <div className="rdp-placeholder-sub">Session <span className="mono">{sessionId}</span></div>
            {notice && <div className={`rdp-placeholder-hint ${notice.kind === 'err' ? 'fs-notice err' : 'fs-notice ok'}`}>{notice.text}</div>}
          </div>
        )}
      </div>
    </div>
  )
}
