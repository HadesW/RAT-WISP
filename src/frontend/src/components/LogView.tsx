import { useCallback, useEffect, useMemo, useState } from 'react'
import { callByName } from '../wails'
import { useT } from '../i18n'

interface LogEntry {
  id: number
  session_id: string
  type: string
  content: string
  timestamp: string
}

export function LogView() {
  const t = useT()
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [typeFilter, setTypeFilter] = useState('')
  const [query, setQuery] = useState('')
  const [sessionFilter, setSessionFilter] = useState('')

  const refresh = useCallback(async () => {
    try {
      const data = await callByName('github.com/user/wisp/services.SessionService.GetAllLogs', 500)
      if (Array.isArray(data)) setLogs(data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 5000)
    return () => clearInterval(t)
  }, [refresh])

  const sessions = useMemo(() => {
    const seen = new Map<string, string>()
    logs.forEach(l => seen.set(l.session_id, l.session_id))
    return Array.from(seen.keys()).sort()
  }, [logs])

  const filtered = useMemo(() => {
    let list = logs
    if (typeFilter) list = list.filter(l => l.type === typeFilter)
    if (sessionFilter) list = list.filter(l => l.session_id === sessionFilter)
    const q = query.trim().toLowerCase()
    if (q) list = list.filter(l => l.content.toLowerCase().includes(q) || l.session_id.toLowerCase().includes(q))
    return list
  }, [logs, typeFilter, sessionFilter, query])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 8, padding: '6px 8px', alignItems: 'center' }}>
        <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">{t('logAllTypes')}</option>
          <option value="input">{t('logInput')}</option>
          <option value="output">{t('logOutput')}</option>
        </select>
        <select className="filter-select" value={sessionFilter} onChange={e => setSessionFilter(e.target.value)}>
          <option value="">{t('logAllSessions')}</option>
          {sessions.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <input
          className="filter-input"
          style={{ flex: 1 }}
          placeholder={t('logSearch')}
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
        <button className="toolbar-btn" onClick={refresh} title="Refresh">⟳</button>
        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{filtered.length}</span>
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="session-table">
          <thead>
            <tr>
              <th style={{ width: 150 }}>{t('logTime')}</th>
              <th style={{ width: 130 }}>{t('logSession')}</th>
              <th style={{ width: 60 }}>{t('logType')}</th>
              <th>{t('logContent')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>{t('logEmpty')}</td></tr>
            ) : (
              filtered.map(l => (
                <tr key={l.id}>
                  <td className="mono">{new Date(l.timestamp).toLocaleString()}</td>
                  <td className="mono">{l.session_id}</td>
                  <td><span className={`log-type ${l.type}`}>{l.type}</span></td>
                  <td className={l.type === 'input' ? 'log-content input' : 'log-content output'}>{l.content}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
