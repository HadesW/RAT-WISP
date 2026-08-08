import { useCallback, useEffect, useState } from 'react'
import { useT } from '../i18n'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

interface FileEntry {
  name: string
  size: number
  mod_time: string
  url: string
}

interface FileServerStatus {
  running: boolean
  url: string
  host: string
  root_dir: string
  port: number
  use_tls: boolean
  files: FileEntry[]
}

interface LocalEntry {
  name: string
  size: number
  is_dir: boolean
  mod_time: string
}

const SVC = 'github.com/user/wisp/services.FileServerService'

function fmtSize(n: number): string {
  if (n >= 1024 * 1024 * 1024) return (n / 1024 / 1024 / 1024).toFixed(1) + ' GB'
  if (n >= 1024 * 1024) return (n / 1024 / 1024).toFixed(1) + ' MB'
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB'
  return n + ' B'
}

export function FileServerPanel() {
  const t = useT()
  const [status, setStatus] = useState<FileServerStatus | null>(null)
  const [rootDir, setRootDir] = useState('')
  const [port, setPort] = useState(8080)
  const [useTLS, setUseTLS] = useState(false)
  // "0.0.0.0" is the default: listen on all interfaces. The backend treats it
  // as "auto" for the displayed URL (picks the machine's LAN address).
  const [host, setHost] = useState('0.0.0.0')
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)

  // Directory browser state
  const [browsing, setBrowsing] = useState(false)
  const [browsePath, setBrowsePath] = useState('')
  const [browseItems, setBrowseItems] = useState<LocalEntry[]>([])
  const [browseErr, setBrowseErr] = useState('')

  const load = useCallback(async () => {
    try {
      const st = await callBackend(SVC + '.GetFileServerStatus') as FileServerStatus
      setStatus(st)
      if (st.root_dir) setRootDir(st.root_dir)
      if (st.port) setPort(st.port)
      setUseTLS(st.use_tls)
      // Keep the default "0.0.0.0" when nothing is configured yet
      if (st.host !== undefined && st.host !== '') setHost(st.host)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const notify = (kind: 'ok' | 'err', text: string) => setNotice({ kind, text })

  const start = async () => {
    setBusy(true)
    setNotice(null)
    try {
      await callBackend(SVC + '.StartFileServer', rootDir, Number(port), useTLS, host.trim())
      await load()
      notify('ok', t('fsStarted'))
    } catch (e) {
      notify('err', t('fsStartFailed') + ': ' + String(e))
    } finally {
      setBusy(false)
    }
  }

  const stop = async () => {
    setBusy(true)
    try {
      await callBackend(SVC + '.StopFileServer')
      await load()
      notify('ok', t('fsStopped2'))
    } catch (e) {
      notify('err', t('fsStopFailed') + ': ' + String(e))
    } finally {
      setBusy(false)
    }
  }

  const openBrowse = async () => {
    setBrowsing(true)
    setBrowseErr('')
    let p = rootDir
    if (!p) {
      try {
        p = (await callBackend('github.com/user/wisp/services.SessionService.GetLocalHomeDir')) as string
      } catch { p = 'C:\\' }
    }
    setBrowsePath(p)
    await refreshBrowse(p)
  }

  const refreshBrowse = async (path: string) => {
    setBrowseErr('')
    try {
      const items = await callBackend('github.com/user/wisp/services.SessionService.ListLocalDir', path) as LocalEntry[]
      setBrowseItems(items || [])
    } catch (e) {
      setBrowseItems([])
      setBrowseErr(t('fsCannotList') + ': ' + String(e))
    }
  }

  const browseUp = async () => {
    const idx = Math.max(browsePath.lastIndexOf('\\'), browsePath.lastIndexOf('/'))
    if (idx > 0) {
      const parent = browsePath.slice(0, idx)
      setBrowsePath(parent)
      await refreshBrowse(parent)
    }
  }

  const browseInto = async (name: string) => {
    const next = browsePath.replace(/[\\/]$/, '') + '\\' + name
    setBrowsePath(next)
    await refreshBrowse(next)
  }

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      notify('ok', t('fsCopyDone') + ': ' + text)
    } catch { /* ignore */ }
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', padding: 12, gap: 10, overflow: 'auto' }}>
      {/* Status */}
      <div className="panel-card">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="status-dot" style={{ background: status?.running ? 'var(--ok)' : 'var(--text-dim)' }} />
          <b>{status?.running ? t('fsRunning') : t('fsStopped')}</b>
          {status?.running && status.url && (
            <span className="fs-url" onClick={() => copy(status.url)} title={t('fsCopy')}>{status.url}</span>
          )}
          <span style={{ marginLeft: 'auto' }}>
            <button className="toolbar-btn" onClick={load}>{t('fsRefresh')}</button>
          </span>
        </div>
      </div>

      {/* Config */}
      <div className="panel-card">
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label style={{ width: 70 }}>{t('fsRootDir')}</label>
            <input
              className="fs-input"
              value={rootDir}
              onChange={e => setRootDir(e.target.value)}
              placeholder="C:\share"
              style={{ flex: 1 }}
            />
            <button className="toolbar-btn" onClick={openBrowse}>{t('fsBrowse')}</button>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label style={{ width: 70 }}>{t('fsPort')}</label>
            <input
              className="fs-input"
              type="number"
              min={1}
              max={65535}
              value={port}
              onChange={e => setPort(Number(e.target.value) || 0)}
              style={{ width: 110 }}
            />
            <label style={{ width: 70, textAlign: 'right', paddingRight: 8 }}>{t('fsHost')}</label>
            <input
              className="fs-input"
              value={host}
              onChange={e => setHost(e.target.value)}
              placeholder={t('fsHostPlaceholder')}
              style={{ flex: 1, minWidth: 200 }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <label style={{ width: 70 }}>{t('fsProtocol')}</label>
            <select className="fs-input" value={useTLS ? 'https' : 'http'} onChange={e => setUseTLS(e.target.value === 'https')} style={{ width: 110 }}>
              <option value="http">http</option>
              <option value="https">https</option>
            </select>
            <span style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
              {!status?.running ? (
                <button className="toolbar-btn primary" onClick={start} disabled={busy}>{t('fsStart')}</button>
              ) : (
                <button className="toolbar-btn" onClick={stop} disabled={busy}>{t('fsStop')}</button>
              )}
            </span>
          </div>
          {notice && <div className={`fs-notice ${notice.kind}`}>{notice.text}</div>}
        </div>
      </div>

      {/* File listing */}
      <div className="panel-card" style={{ flex: 1, minHeight: 160, display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '4px 0', fontWeight: 600 }}>{t('fsServedFiles')}</div>
        {!status?.running ? (
          <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '8px 0' }}>
            {t('fsStoppedHint')}
          </div>
        ) : status.files.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: '8px 0' }}>
            {t('fsNoFiles').replace('{dir}', status.root_dir)}
          </div>
        ) : (
          <table className="file-table">
            <thead>
              <tr><th>{t('fsName')}</th><th>{t('fsSize')}</th><th>{t('fsModified')}</th><th>{t('fsDownloadURL')}</th><th /></tr>
            </thead>
            <tbody>
              {status.files.map(f => (
                <tr key={f.name}>
                  <td className="mono">{f.name}</td>
                  <td>{fmtSize(f.size)}</td>
                  <td className="mono">{f.mod_time}</td>
                  <td className="mono fs-url" title={t('fsCopy')} onClick={() => copy(f.url)}>{f.url}</td>
                  <td>
                    <button className="toolbar-btn" onClick={() => copy(f.url)}>{t('fsCopy')}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Directory browser overlay */}
      {browsing && (
        <div className="fs-browse-backdrop" onClick={() => setBrowsing(false)}>
          <div className="fs-browse" onClick={e => e.stopPropagation()}>
            <div className="fs-browse-path mono">{browsePath}</div>
            {browseErr && <div className="fs-notice err">{browseErr}</div>}
            <div className="fs-browse-list">
              <div className="fs-browse-item fs-browse-up" onClick={browseUp}>{t('fsParent')}</div>
              {browseItems.map(d => d.is_dir ? (
                <div key={d.name} className="fs-browse-item fs-browse-dir" onClick={() => browseInto(d.name)}>📁 {d.name}</div>
              ) : (
                <div key={d.name} className="fs-browse-item fs-browse-file">📄 {d.name} <span className="fs-browse-size">{fmtSize(d.size)}</span></div>
              ))}
              {browseItems.length === 0 && !browseErr && (
                <div style={{ color: 'var(--text-muted)', fontSize: 12, padding: 6 }}>{t('fsEmptyDir')}</div>
              )}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
              <button className="toolbar-btn" onClick={() => setBrowsing(false)}>{t('fsCancel')}</button>
              <button
                className="toolbar-btn primary"
                onClick={() => { setRootDir(browsePath); setBrowsing(false) }}
              >
                {t('fsUseThisDir')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
