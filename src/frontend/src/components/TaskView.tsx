import { useCallback, useEffect, useMemo, useState } from 'react'
import { callByName } from '../wails'
import { useT } from '../i18n'
import { ContextMenu, ContextMenuItem } from './ContextMenu'
import { ConfirmDialog } from './ConfirmDialog'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

interface TaskRow {
  id: string
  session_id: string
  command_id: number
  args: string
  status: string
  result: string
  created_at: string
}

const STATUS_COLORS: Record<string, string> = {
  pending: '#f0b429',
  sent: '#58a6ff',
  completed: '#2ea043',
  failed: '#e5484d',
  downloading: '#bc8cff',
}

export function TaskView() {
  const t = useT()
  const [tasks, setTasks] = useState<TaskRow[]>([])
  const [statusFilter, setStatusFilter] = useState('')
  const [menu, setMenu] = useState<{ x: number; y: number; items: ContextMenuItem[] } | null>(null)
  const [confirm, setConfirm] = useState<{ title: string; onOk: () => void } | null>(null)

  const refresh = useCallback(async () => {
    try {
      const data = await callByName('github.com/user/wisp/services.SessionService.GetAllTasks', 300)
      if (Array.isArray(data)) setTasks(data)
    } catch { /* ignore */ }
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 5000)
    return () => clearInterval(t)
  }, [refresh])

  const filtered = useMemo(() => {
    if (!statusFilter) return tasks
    return tasks.filter(t => t.status === statusFilter)
  }, [tasks, statusFilter])

  const summary = useMemo(() => {
    const c: Record<string, number> = { pending: 0, sent: 0, completed: 0, failed: 0 }
    tasks.forEach(t => { if (c[t.status] !== undefined) c[t.status]++ })
    return c
  }, [tasks])

  const openMenu = (e: React.MouseEvent, row: TaskRow) => {
    e.preventDefault()
    setMenu({
      x: e.clientX,
      y: e.clientY,
      items: [
        {
          label: t('taskRerun'),
          onClick: () => callBackend('github.com/user/wisp/services.SessionService.RerunTask', row.id).then(() => refresh()),
        },
        {
          label: t('taskDelete'),
          danger: true,
          onClick: () => callBackend('github.com/user/wisp/services.SessionService.DeleteTask', row.id).then(() => refresh()),
        },
      ],
    })
  }

  const clearAll = () => {
    setConfirm({
      title: t('taskClearConfirm'),
      onOk: () => {
        // Clear per session via the API
        const ids = [...new Set(tasks.map(t => t.session_id))]
        Promise.all(ids.map(id => callBackend('github.com/user/wisp/services.SessionService.ClearTasks', id))).then(refresh)
      },
    })
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 8, padding: '6px 8px', alignItems: 'center' }}>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">{t('taskAllStatus')}</option>
          <option value="pending">{t('stPending')}</option>
          <option value="sent">{t('stSent')}</option>
          <option value="completed">{t('stCompleted')}</option>
          <option value="failed">{t('stFailed')}</option>
          <option value="downloading">{t('stDownloading')}</option>
        </select>
        <button className="toolbar-btn" onClick={refresh} title="Refresh">⟳</button>
        <button className="toolbar-btn" onClick={clearAll} title={t('taskClearAll')}>{t('taskClearAll')}</button>
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 11 }}>
          P {summary.pending} · S {summary.sent} · C {summary.completed} · F {summary.failed}
        </span>
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="session-table">
          <thead>
            <tr>
              <th style={{ width: 70 }}>{t('taskStatus')}</th>
              <th style={{ width: 130 }}>{t('logSession')}</th>
              <th style={{ width: 80 }}>{t('taskCmd')}</th>
              <th style={{ width: 150 }}>{t('taskArgs')}</th>
              <th>{t('taskResult')}</th>
              <th style={{ width: 150 }}>{t('taskCreated')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>{t('tasksEmpty')}</td></tr>
            ) : (
              filtered.map(row => (
                <tr key={row.id} onContextMenu={e => openMenu(e, row)}>
                  <td><span className="log-type" style={{ color: STATUS_COLORS[row.status] || '#888', background: 'rgba(255,255,255,0.05)' }}>{t('st' + cap(row.status))}</span></td>
                  <td className="mono">{row.session_id}</td>
                  <td className="mono">{row.command_id}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{truncate(row.args, 40)}</td>
                  <td className="mono" style={{ fontSize: 11 }}>{truncate(row.result, 60)}</td>
                  <td className="mono">{row.created_at ? new Date(row.created_at).toLocaleString() : ''}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      {confirm && (
        <ConfirmDialog
          title={confirm.title}
          onCancel={() => setConfirm(null)}
          onOk={() => { setConfirm(null); confirm.onOk() }}
        />
      )}
    </div>
  )
}

function truncate(s: string, n: number): string {
  if (!s) return ''
  return s.length > n ? s.slice(0, n) + '…' : s
}

function cap(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s
}
