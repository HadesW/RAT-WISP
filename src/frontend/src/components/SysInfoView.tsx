import { useCallback, useEffect, useState } from 'react'
import { useSessionStore } from '../stores/useSessionStore'
import { useT } from '../i18n'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

const POLL_MS = 400
const TIMEOUT_MS = 60000

interface InfoPair {
  key: string
  value: string
}

function parseKV(text: string): InfoPair[] {
  const rows: InfoPair[] = []
  for (const line of text.split('\n')) {
    const i = line.indexOf(':')
    if (i > 0) rows.push({ key: line.slice(0, i).trim(), value: line.slice(i + 1).trim() })
  }
  return rows
}

// SysInfoView shows the machine information of a session. The session table
// rows already carry the basic fingerprint (hostname / user / OS / addresses);
// a live `sysinfo` command fetches the deeper platform details (Windows build,
// Linux distro version, ...) which are displayed below it.
export function SysInfoView({ sessionId }: { sessionId: string }) {
  const t = useT()
  const session = useSessionStore(s => s.sessions.find(x => x.id === sessionId))
  const [extra, setExtra] = useState<InfoPair[] | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const refresh = useCallback(async () => {
    if (!sessionId) return
    setLoading(true)
    setError('')
    setExtra(null)
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.RunCommand', sessionId, 'sysinfo', '{}')
      const deadline = Date.now() + TIMEOUT_MS
      let task: any = null
      while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, POLL_MS))
        task = await callBackend('github.com/user/wisp/services.SessionService.GetTask', taskID)
        if (task && (task.status === 'completed' || task.status === 'failed')) break
      }
      if (!task || (task.status !== 'completed' && task.status !== 'failed')) {
        setError('sysinfo timed out (agent may be asleep or offline)')
      } else if (task.status === 'failed') {
        setError(task.result || 'sysinfo failed')
      } else {
        setExtra(parseKV(task.result || ''))
      }
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [sessionId])

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  const base: InfoPair[] = session
    ? [
        { key: t('sessionHostname'), value: session.hostname || '-' },
        { key: t('sessionUser'), value: session.domain ? `${session.domain}\\${session.username}` : session.username },
        { key: t('sessionOS'), value: session.os || '-' },
        { key: t('sessionArch'), value: session.arch || '-' },
        { key: t('sessionIntIP'), value: session.internal_ip || '-' },
        { key: t('sessionExtIP'), value: session.external_ip || '-' },
        { key: t('sessionPID'), value: String(session.pid || '-') },
        { key: t('sessionProcess'), value: session.process_name || '-' },
        { key: t('sessionProtocol'), value: (session.protocol || '-').toUpperCase() },
        { key: t('sessionElevated'), value: session.is_elevated ? 'Yes' : 'No' },
        { key: t('sessionFirstSeen'), value: session.first_seen || '-' },
        { key: t('sessionLastSeen'), value: session.last_seen || '-' },
        { key: t('sessionSleep'), value: session.sleep_interval > 0 ? `${session.sleep_interval}ms${session.jitter > 0 ? ` (+${session.jitter}%)` : ''}` : '-' },
      ]
    : []

  const renderTable = (rows: InfoPair[]) => (
    <table className="session-table" style={{ minWidth: 0 }}>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>
            <td style={{ width: 220, padding: '6px 10px', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>{r.key}</td>
            <td className="mono" style={{ padding: '6px 10px', borderBottom: '1px solid var(--border)', wordBreak: 'break-all' }}>{r.value}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div className="fm-pane-toolbar">
        <div className="fm-side">
          <span className="fm-side-label">{t('menuComputerInfo')}</span>
          <button className="toolbar-btn" onClick={refresh} disabled={loading} title={t('sysInfoRefresh')}>⟳</button>
          {loading && <span className="shell-busy">{t('sysInfoLoading')}</span>}
        </div>
        <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 12 }}>{sessionId}</span>
      </div>
      <div style={{ flex: 1, overflow: 'auto', padding: '10px 14px' }}>
        <h3 style={{ margin: '4px 0 8px', fontSize: 13, color: 'var(--text-muted)' }}>{t('sysInfoBasic')}</h3>
        {renderTable(base)}
        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
        <h3 style={{ margin: '18px 0 8px', fontSize: 13, color: 'var(--text-muted)' }}>{t('sysInfoDetailed')}</h3>
        {extra === null && !error ? (
          <div style={{ padding: 12, color: 'var(--text-muted)' }}>{t('sysInfoLoading')}...</div>
        ) : extra && extra.length > 0 ? (
          renderTable(extra)
        ) : (
          <div style={{ padding: 12, color: 'var(--text-muted)' }}>{t('sysInfoEmpty')}</div>
        )}
      </div>
    </div>
  )
}
