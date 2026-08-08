import { useCallback, useEffect, useRef, useState } from 'react'
import { callByName } from '../wails'
import { useT } from '../i18n'
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

function joinPath(path: string, name: string): string {
  if (!path) return name
  return path.replace(/[\\/]+$/, '') + '\\' + name
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
}

export function FileManager({ sessionId }: { sessionId: string | null }) {
  const t = useT()
  // Local (operator) side
  const [localPath, setLocalPath] = useState('C:\\Users')
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
    if (!localPath) return
    setLocalError('')
    try {
      const data = await callBackend(
        'github.com/user/wisp/services.SessionService.ListLocalDir',
        localPath,
      )
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
      const resolved = parsed.path || dir
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

  useEffect(() => {
    refreshTransfers()
    const t = setInterval(refreshTransfers, 3000)
    return () => clearInterval(t)
  }, [refreshTransfers])

  const goUpLocal = () => {
    const i = Math.max(localPath.lastIndexOf('\\'), localPath.lastIndexOf('/'))
    setLocalPath(i > 0 ? localPath.slice(0, i) : '')
  }
  const goUpRemote = () => {
    if (!remotePath) return
    const i = Math.max(remotePath.lastIndexOf('\\'), remotePath.lastIndexOf('/'))
    setRemotePath(i > 0 ? remotePath.slice(0, i) : '')
  }

  const downloadSelected = async () => {
    if (!sessionId || remoteSelected.size === 0) return
    for (const name of remoteSelected) {
      const remote = joinPath(remotePath, name)
      const local = joinPath(localPath, name)
      await callBackend('github.com/user/wisp/services.SessionService.DownloadFile', sessionId, remote, local)
    }
    refreshTransfers()
  }

  const uploadSelected = async () => {
    if (!sessionId || localSelected.size === 0) return
    for (const name of localSelected) {
      const local = joinPath(localPath, name)
      const remote = joinPath(remotePath, name)
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

  const enterRemoteDir = (name: string) => loadRemote(joinPath(remotePath, name))
  const enterLocalDir = (name: string) => setLocalPath(joinPath(localPath, name))

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
              onClick: () => setConfirmDelete({ name, path: joinPath(remotePath, name) }),
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
