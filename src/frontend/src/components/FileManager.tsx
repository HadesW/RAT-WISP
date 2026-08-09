import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { callByName } from '../wails'
import { useT } from '../i18n'
import { useSessionStore } from '../stores/useSessionStore'
import { ContextMenu, ContextMenuItem } from './ContextMenu'
import { ConfirmDialog } from './ConfirmDialog'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

interface FsEntry {
  name: string
  is_dir: boolean
  size: number
  mod: string
}

interface ListResult {
  cwd?: string
  path?: string
  entries: FsEntry[]
  error?: string
}

interface LocalEntry {
  name: string
  size: number
  is_dir: boolean
  mod_time: string
}

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

interface MenuState { x: number; y: number; items: ContextMenuItem[] }

// joinPath joins a directory and an entry name using the target platform's
// separator. Using a fixed backslash broke Linux paths ("/home/user\file" is a
// valid single file name on Linux, so downloads silently failed).
function joinPath(path: string, name: string, sep: string): string {
  if (!path) return name
  return path.replace(/[\\/]+$/, '') + sep + name
}

// localSep is the operator machine's own path separator.
const localSep = navigator.userAgent.includes('Windows') ? '\\' : '/'

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
}

export function FileManager({ sessionId }: { sessionId: string | null }) {
  const t = useT()
  // Path separator of the remote (agent) platform: backslash on Windows,
  // forward slash everywhere else.
  const sessions = useSessionStore(s => s.sessions)
  const remoteSep = useMemo(() => {
    const os = (sessions.find(s => s.id === sessionId)?.os || '').toLowerCase()
    return os.includes('windows') ? '\\' : '/'
  }, [sessions, sessionId])

  // Local (operator) side. localPath === '' means the drive/roots view
  // ("This PC"); double-clicking a drive enters it. The last visited local
  // directory is remembered across sessions via localStorage.
  const [localPath, setLocalPath] = useState(() => localStorage.getItem('wisp-local-path') || '')
  const [localEntries, setLocalEntries] = useState<LocalEntry[]>([])
  const [localSelected, setLocalSelected] = useState<Set<string>>(new Set())
  const [localError, setLocalError] = useState('')

  // Remote (agent) side
  const [remotePath, setRemotePath] = useState('')
  const [remoteEntries, setRemoteEntries] = useState<FsEntry[]>([])
  const [remoteSelected, setRemoteSelected] = useState<Set<string>>(new Set())
  const [remoteError, setRemoteError] = useState('')

  // Transfers
  const [transfers, setTransfers] = useState<TransferRow[]>([])

  const [menu, setMenu] = useState<MenuState | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<{ name: string; path: string } | null>(null)

  const paths = useRef<Record<string, string>>({})

  const refreshLocal = useCallback(async () => {
    setLocalError('')
    try {
      // localPath === '' = roots view ("This PC"): list local drives/roots.
      const data = localPath
        ? await callBackend('github.com/user/wisp/services.SessionService.ListLocalDir', localPath)
        : await callBackend('github.com/user/wisp/services.SessionService.ListLocalDrives')
      if (Array.isArray(data)) {
        setLocalEntries(data)
        setLocalSelected(new Set())
      }
    } catch (e) {
      setLocalError(String(e))
    }
  }, [localPath])

  const pollTask = useCallback(async (taskID: string, timeoutMs = 10000): Promise<any> => {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, 400))
      const task = await callBackend('github.com/user/wisp/services.SessionService.GetTask', taskID)
      if (task && (task.status === 'completed' || task.status === 'failed')) return task
    }
    throw new Error('task timed out')
  }, [])

  const loadRemote = useCallback(async (dir: string) => {
    if (!sessionId) return
    setRemoteError('')
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.FileList', sessionId, dir)
      const task = await pollTask(taskID)
      if (task.status === 'failed') {
        setRemoteError(task.result || 'listing failed')
        return
      }
      const parsed: ListResult = JSON.parse(task.result || '{"entries":[]}')
      if (parsed.error) {
        setRemoteError(parsed.error)
        return
      }
      setRemoteEntries(parsed.entries || [])
      setRemoteSelected(new Set())
      // The roots marker is shown as an empty path (home view) in the box.
      const resolved = parsed.path && parsed.path !== '__roots__' ? parsed.path : ''
      setRemotePath(resolved)
      paths.current[sessionId] = resolved
    } catch (e) {
      setRemoteError(String(e))
    }
  }, [sessionId, pollTask])

  const refreshTransfers = useCallback(async () => {
    try {
      const data = await callBackend('github.com/user/wisp/services.SessionService.GetAllTransfers', 200)
      if (Array.isArray(data)) setTransfers(data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    if (!sessionId) return
    const last = paths.current[sessionId]
    if (last) setRemotePath(last)
    loadRemote(last || '')
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // Refresh the local pane automatically whenever the local directory changes
  // (double-click / up / home / remembered path). Without this, entering a
  // folder only updated the address box and required a manual refresh.
  useEffect(() => {
    refreshLocal()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [localPath])

  useEffect(() => {
    refreshTransfers()
    const t = setInterval(refreshTransfers, 3000)
    return () => clearInterval(t)
  }, [refreshTransfers])

  // setLocalPathAndRemember sets the local directory and persists it.
  const setLocalPathAndRemember = (p: string) => {
    setLocalPath(p)
    try { localStorage.setItem('wisp-local-path', p) } catch { /* ignore */ }
  }

  const goUpLocal = () => {
    // "" (roots view) -> disabled; "C:\" -> "" (back to drives); "C:\a" -> "C:\"
    if (!localPath) return
    const i = Math.max(localPath.lastIndexOf('\\'), localPath.lastIndexOf('/'))
    setLocalPathAndRemember(i > 0 ? localPath.slice(0, i) : '')
  }
  const goUpRemote = () => {
    if (!remotePath) return
    const i = Math.max(remotePath.lastIndexOf('\\'), remotePath.lastIndexOf('/'))
    const parent = i > 0 ? remotePath.slice(0, i) : ''
    loadRemote(parent)
  }

  const downloadSelected = async () => {
    if (!sessionId || remoteSelected.size === 0) return
    for (const name of remoteSelected) {
      const remote = joinPath(remotePath, name, remoteSep)
      const local = joinPath(localPath, name, localSep)
      await callBackend('github.com/user/wisp/services.SessionService.DownloadFile', sessionId, remote, local)
    }
    refreshTransfers()
  }

  const uploadSelected = async () => {
    if (!sessionId || localSelected.size === 0) return
    for (const name of localSelected) {
      const local = joinPath(localPath, name, localSep)
      const remote = joinPath(remotePath, name, remoteSep)
      await callBackend('github.com/user/wisp/services.SessionService.UploadFile', sessionId, local, remote)
    }
    refreshTransfers()
  }

  const toggleSelect = (set: Set<string>, name: string, current: Set<string>) => {
    const next = new Set(set)
    if (current.has(name)) next.delete(name)
    else next.add(name)
    return next
  }

  const enterRemoteDir = (name: string) => loadRemote(joinPath(remotePath, name, remoteSep))
  const enterLocalDir = (name: string) => {
    // In the roots view, entries are drive roots like "C:\" — enter directly.
    if (!localPath) { setLocalPathAndRemember(name); return }
    setLocalPathAndRemember(joinPath(localPath, name, localSep))
  }

  const openLocalMenu = (e: React.MouseEvent, name: string, isDir: boolean) => {
    e.preventDefault()
    setLocalSelected(new Set([name]))
    setMenu({
      x: e.clientX, y: e.clientY,
      items: isDir
        ? [
            { label: t('filesOpen'), onClick: () => enterLocalDir(name) },
            { label: t('filesUploadToAgent'), onClick: uploadSelected },
          ]
        : [
            { label: t('filesUploadToAgent'), onClick: uploadSelected },
          ],
    })
  }
  const openRemoteMenu = (e: React.MouseEvent, name: string, isDir: boolean) => {
    e.preventDefault()
    setRemoteSelected(new Set([name]))
    setMenu({
      x: e.clientX, y: e.clientY,
      items: isDir
        ? [
            { label: t('filesOpen'), onClick: () => enterRemoteDir(name) },
            { label: t('filesDownloadToLocal'), onClick: downloadSelected },
          ]
        : [
            { label: t('filesDownloadToLocal'), onClick: downloadSelected },
            { separator: true },
            {
              label: t('filesDelete'),
              danger: true,
              onClick: () => setConfirmDelete({ name, path: joinPath(remotePath, name, remoteSep) }),
            },
          ],
    })
  }

  if (!sessionId) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)' }}>
        {t('filesNoSelection')}
      </div>
    )
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div className="fm-pane-toolbar">
        <div className="fm-side">
          <span className="fm-side-label">{t('filesLocal')}</span>
          <button className="toolbar-btn" onClick={() => setLocalPathAndRemember('')} title={t('filesHome')}>⌂</button>
          <button className="toolbar-btn" onClick={goUpLocal} title={t('filesUp')}>↑</button>
          <button className="toolbar-btn" onClick={refreshLocal} title={t('filesRefresh')}>⟳</button>
          <input
            className="filter-input"
            style={{ flex: 1 }}
            value={localPath}
            onChange={e => setLocalPath(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') refreshLocal() }}
            placeholder={t('filesLocalPathPlaceholder')}
          />
        </div>
        <div className="fm-arrows">
          <button className="toolbar-btn" onClick={downloadSelected} title={t('filesDownloadToLocal')} disabled={remoteSelected.size === 0}>←</button>
          <button className="toolbar-btn" onClick={uploadSelected} title={t('filesUploadToAgent')} disabled={localSelected.size === 0}>→</button>
        </div>
        <div className="fm-side">
          <span className="fm-side-label">{t('filesAgent')}</span>
          <button className="toolbar-btn" onClick={() => loadRemote('')} title={t('filesHome')}>⌂</button>
          <button className="toolbar-btn" onClick={goUpRemote} title={t('filesUp')}>↑</button>
          <button className="toolbar-btn" onClick={() => loadRemote(remotePath)} title={t('filesRefresh')}>⟳</button>
          <input
            className="filter-input"
            style={{ flex: 1 }}
            value={remotePath}
            onChange={e => setRemotePath(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') loadRemote(remotePath) }}
            placeholder={t('filesRemotePathPlaceholder')}
          />
        </div>
      </div>

      <div className="fm-panes">
        <div className="fm-pane">
          {localError && <div className="fm-error">{localError}</div>}
          <div className="fm-table-wrap">
            <table className="session-table">
              <thead>
                <tr>
                  <th style={{ width: 26 }}></th>
                  <th style={{ width: 36 }}>{t('filesType')}</th>
                  <th>{t('filesName')}</th>
                  <th style={{ width: 100 }}>{t('filesSize')}</th>
                  <th style={{ width: 150 }}>{t('filesModified')}</th>
                </tr>
              </thead>
              <tbody>
                {localEntries.length === 0 ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', padding: 16, color: 'var(--text-muted)' }}>{localError ? '' : t('filesPressEnter')}</td></tr>
                ) : (
                  localEntries.map(e => (
                    <tr
                      key={e.name}
                      className={localSelected.has(e.name) ? 'selected' : ''}
                      onClick={() => setLocalSelected(toggleSelect(localSelected, e.name, localSelected))}
                      onDoubleClick={() => e.is_dir && enterLocalDir(e.name)}
                      onContextMenu={ev => openLocalMenu(ev, e.name, e.is_dir)}
                    >
                      <td><input type="checkbox" checked={localSelected.has(e.name)} onChange={() => setLocalSelected(toggleSelect(localSelected, e.name, localSelected))} onClick={e => e.stopPropagation()} /></td>
                      <td>{e.is_dir ? '📁' : '📄'}</td>
                      <td>{e.name}</td>
                      <td className="mono">{e.is_dir ? '—' : formatSize(e.size)}</td>
                      <td className="mono">{e.mod_time ? new Date(e.mod_time).toLocaleString() : ''}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="fm-pane">
          {remoteError && <div className="fm-error">{remoteError}</div>}
          <div className="fm-table-wrap">
            <table className="session-table">
              <thead>
                <tr>
                  <th style={{ width: 26 }}></th>
                  <th style={{ width: 36 }}>{t('filesType')}</th>
                  <th>{t('filesName')}</th>
                  <th style={{ width: 100 }}>{t('filesSize')}</th>
                  <th style={{ width: 150 }}>{t('filesModified')}</th>
                </tr>
              </thead>
              <tbody>
                {remoteEntries.length === 0 ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', padding: 16, color: 'var(--text-muted)' }}>{t('fsEmptyDir')}</td></tr>
                ) : (
                  remoteEntries.map(e => (
                    <tr
                      key={e.name}
                      className={remoteSelected.has(e.name) ? 'selected' : ''}
                      onClick={() => setRemoteSelected(toggleSelect(remoteSelected, e.name, remoteSelected))}
                      onDoubleClick={() => e.is_dir && enterRemoteDir(e.name)}
                      onContextMenu={ev => openRemoteMenu(ev, e.name, e.is_dir)}
                    >
                      <td><input type="checkbox" checked={remoteSelected.has(e.name)} onChange={() => setRemoteSelected(toggleSelect(remoteSelected, e.name, remoteSelected))} onClick={e => e.stopPropagation()} /></td>
                      <td>{e.is_dir ? '📁' : '📄'}</td>
                      <td>{e.name}</td>
                      <td className="mono">{e.is_dir ? '—' : formatSize(e.size)}</td>
                      <td className="mono">{e.mod ? new Date(e.mod).toLocaleString() : ''}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="fm-transfers">
        <div className="fm-transfers-header">{t('filesTransferList')} ({transfers.length})</div>
        <div className="fm-transfers-body">
          {transfers.length === 0 ? (
            <div style={{ padding: 8, color: 'var(--text-muted)', textAlign: 'center' }}>{t('filesNoTransfers')}</div>
          ) : (
            <table className="session-table">
              <thead>
                <tr>
                  <th style={{ width: 70 }}>{t('filesDir')}</th>
                  <th>{t('filesLocal')}</th>
                  <th>{t('filesRemote')}</th>
                  <th style={{ width: 90 }}>{t('filesSize')}</th>
                  <th style={{ width: 80 }}>{t('taskStatus')}</th>
                </tr>
              </thead>
              <tbody>
                {transfers.slice(0, 30).map(t => (
                  <tr key={t.id}>
                    <td>
                      <span className="log-type" style={{
                        color: t.direction === 'upload' ? '#58a6ff' : '#bc8cff',
                        background: 'rgba(255,255,255,0.05)',
                      }}>{t.direction}</span>
                    </td>
                    <td className="mono" style={{ fontSize: 11 }}>{t.local_path || '—'}</td>
                    <td className="mono" style={{ fontSize: 11 }}>{t.remote_path || '—'}</td>
                    <td className="mono">{formatSize(t.size)}</td>
                    <td>
                      <span className="log-type" style={{
                        color: t.status === 'completed' ? '#2ea043' : t.status === 'failed' ? '#e5484d' : '#f0b429',
                        background: 'rgba(255,255,255,0.05)',
                      }}>{t.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      {confirmDelete && (
        <ConfirmDialog
          title={`${t('filesDeleteConfirm')} ${confirmDelete.name}?`}
          onCancel={() => setConfirmDelete(null)}
          onOk={() => {
            const c = confirmDelete
            setConfirmDelete(null)
            callBackend('github.com/user/wisp/services.SessionService.FileRemove', sessionId!, c.path).then(() => loadRemote(remotePath))
          }}
        />
      )}
    </div>
  )
}
