import { useCallback, useEffect, useState } from 'react'
import { useSessionStore } from '../stores/useSessionStore'
import { useT } from '../i18n'
import { ContextMenu, ContextMenuItem } from './ContextMenu'
import { ConfirmDialog } from './ConfirmDialog'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

const POLL_MS = 400
const TIMEOUT_MS = 60000

interface ProcRow {
  pid: string
  name: string
  user: string
  mem: string
}

interface MenuState { x: number; y: number; items: ContextMenuItem[] }

// splitCSV parses a tasklist /FO CSV line such as
//   "System Idle Process","0","Services","0","8 K"
// handling quoted fields and embedded commas.
function splitCSV(line: string): string[] {
  const out: string[] = []
  let cur = ''
  let inQ = false
  for (const ch of line) {
    if (ch === '"') { inQ = !inQ; continue }
    if (ch === ',' && !inQ) { out.push(cur.trim()); cur = ''; continue }
    cur += ch
  }
  out.push(cur.trim())
  return out
}

// parseWindows parses tasklist /FO CSV output.
function parseWindows(text: string): ProcRow[] {
  const rows: ProcRow[] = []
  for (const line of text.split('\n')) {
    const f = splitCSV(line)
    if (f.length < 2 || !/^\d+$/.test(f[1])) continue
    rows.push({ pid: f[1], name: f[0], user: f[2] || '-', mem: f[4] || '-' })
  }
  return rows
}

// parseUnix parses `ps -eo pid,user,comm` output (space separated).
function parseUnix(text: string): ProcRow[] {
  const rows: ProcRow[] = []
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/)
    if (f.length < 3 || !/^\d+$/.test(f[0])) continue
    rows.push({ pid: f[0], name: f.slice(2).join(' '), user: f[1], mem: '-' })
  }
  return rows
}

// ProcessView lists the processes running on the target. It issues a `ps`
// command and renders the result as a sortable table; the context menu can
// terminate a process via the `kill` command. Windows output is tasklist CSV,
// Unix output is `ps -eo pid,user,comm`.
export function ProcessView({ sessionId }: { sessionId: string }) {
  const t = useT()
  const sessions = useSessionStore(s => s.sessions)
  const isWindows = (sessions.find(s => s.id === sessionId)?.os || '').toLowerCase().includes('windows')

  const [rows, setRows] = useState<ProcRow[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [menu, setMenu] = useState<MenuState | null>(null)
  const [confirmKill, setConfirmKill] = useState<ProcRow | null>(null)
  const [filter, setFilter] = useState('')

  const pollTask = useCallback(async (taskID: string): Promise<any> => {
    const deadline = Date.now() + TIMEOUT_MS
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, POLL_MS))
      const task = await callBackend('github.com/user/wisp/services.SessionService.GetTask', taskID)
      if (task && (task.status === 'completed' || task.status === 'failed')) return task
    }
    throw new Error('ps timed out (agent may be asleep or offline)')
  }, [])

  const refresh = useCallback(async () => {
    if (!sessionId) return
    setLoading(true)
    setError('')
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.RunCommand', sessionId, 'ps', '{}')
      const task = await pollTask(taskID)
      if (task.status === 'failed') {
        setError(task.result || 'ps failed')
        return
      }
      const text = task.result || ''
      setRows(isWindows ? parseWindows(text) : parseUnix(text))
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [sessionId, isWindows, pollTask])

  useEffect(() => {
    refresh()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  const killProc = async (p: ProcRow) => {
    setConfirmKill(null)
    try {
      await callBackend('github.com/user/wisp/services.SessionService.RunCommand', sessionId, 'kill', JSON.stringify({ pid: p.pid }))
      // Give the kill a moment to take effect, then re-list.
      setTimeout(refresh, 800)
    } catch (e) {
      setError(String(e))
    }
  }

  const openMenu = (e: React.MouseEvent, p: ProcRow) => {
    e.preventDefault()
    setMenu({
      x: e.clientX,
      y: e.clientY,
      items: [
        { label: t('procKill'), danger: true, onClick: () => setConfirmKill(p) },
      ],
    })
  }

  const shown = filter
    ? rows.filter(r => r.name.toLowerCase().includes(filter.toLowerCase()) || r.pid.includes(filter))
    : rows

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div className="fm-pane-toolbar">
        <div className="fm-side">
          <span className="fm-side-label">{t('menuProcessManagement')}</span>
          <button className="toolbar-btn" onClick={refresh} disabled={loading} title={t('procRefresh')}>⟳</button>
          {loading && <span className="shell-busy">{t('procLoading')}</span>}
        </div>
        <input
          className="filter-input"
          style={{ maxWidth: 240, marginRight: 8 }}
          placeholder={t('procFilter')}
          value={filter}
          onChange={e => setFilter(e.target.value)}
        />
        <span className="mono" style={{ color: 'var(--text-muted)', fontSize: 12 }}>{sessionId} · {shown.length} / {rows.length}</span>
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        {error && <div className="error" style={{ padding: 10 }}>{error}</div>}
        <table className="session-table">
          <thead>
            <tr>
              <th style={{ width: 90 }}>{t('procPid')}</th>
              <th>{t('procName')}</th>
              {!isWindows && <th style={{ width: 160 }}>{t('procUser')}</th>}
              {isWindows && <th style={{ width: 160 }}>{t('procSession')}</th>}
              {isWindows && <th style={{ width: 110 }}>{t('procMem')}</th>}
            </tr>
          </thead>
          <tbody>
            {shown.length === 0 ? (
              <tr><td colSpan={4} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>{t('procEmpty')}</td></tr>
            ) : (
              shown.map(p => (
                <tr key={p.pid} onContextMenu={e => openMenu(e, p)} title={t('procKillHint')}>
                  <td className="mono">{p.pid}</td>
                  <td className="mono">{p.name}</td>
                  {!isWindows && <td>{p.user}</td>}
                  {isWindows && <td>{p.user}</td>}
                  {isWindows && <td>{p.mem}</td>}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      {confirmKill && (
        <ConfirmDialog
          title={`${t('procKill')} — ${confirmKill.name} (${confirmKill.pid})`}
          message={t('procKillConfirm')}
          onCancel={() => setConfirmKill(null)}
          onOk={() => killProc(confirmKill)}
        />
      )}
    </div>
  )
}
