import { useCallback, useEffect, useMemo, useState } from 'react'
import { callByName } from '../wails'
import { useT } from '../i18n'

interface TransferRow {
  id: number
  session_id: string
  direction: string
  local_path: string
  remote_path: string
  size: number
  status: string
  created_at: string
}

export function FileTransferView() {
  const t = useT()
  const [transfers, setTransfers] = useState<TransferRow[]>([])
  const [dirFilter, setDirFilter] = useState('')

  const refresh = useCallback(async () => {
    try {
      const data = await callByName('github.com/user/wisp/services.SessionService.GetAllTransfers', 200)
      if (Array.isArray(data)) setTransfers(data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 5000)
    return () => clearInterval(t)
  }, [refresh])

  const filtered = useMemo(() => {
    if (!dirFilter) return transfers
    return transfers.filter(t => t.direction === dirFilter)
  }, [transfers, dirFilter])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 8, padding: '6px 8px', alignItems: 'center' }}>
        <select className="filter-select" value={dirFilter} onChange={e => setDirFilter(e.target.value)}>
          <option value="">{t('transferAllDir')}</option>
          <option value="upload">{t('stUpload')}</option>
          <option value="download">{t('stDownload')}</option>
        </select>
        <button className="toolbar-btn" onClick={refresh} title="Refresh">⟳</button>
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 11 }}>{filtered.length} {t('transferCount')}</span>
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="session-table">
          <thead>
            <tr>
              <th style={{ width: 90 }}>{t('transferDirection')}</th>
              <th style={{ width: 130 }}>{t('logSession')}</th>
              <th>{t('transferLocal')}</th>
              <th>{t('transferRemote')}</th>
              <th style={{ width: 90 }}>{t('transferSize')}</th>
              <th style={{ width: 80 }}>{t('taskStatus')}</th>
              <th style={{ width: 150 }}>{t('taskCreated')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>{t('transfersEmpty')}</td></tr>
            ) : (
              filtered.map(row => (
                <tr key={row.id}>
                  <td>
                    <span className="log-type" style={{
                      color: row.direction === 'upload' ? '#58a6ff' : '#bc8cff',
                      background: 'rgba(255,255,255,0.05)',
                    }}>
                      {t('st' + cap(row.direction))}
                    </span>
                  </td>
                  <td className="mono">{row.session_id}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{row.local_path}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{row.remote_path}</td>
                  <td className="mono">{formatBytes(row.size)}</td>
                  <td>
                    <span className="log-type" style={{
                      color: row.status === 'completed' ? '#2ea043' : row.status === 'failed' ? '#e5484d' : '#f0b429',
                      background: 'rgba(255,255,255,0.05)',
                    }}>{t('st' + cap(row.status))}</span>
                  </td>
                  <td className="mono">{row.created_at ? new Date(row.created_at).toLocaleString() : ''}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
}

function cap(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s
}
