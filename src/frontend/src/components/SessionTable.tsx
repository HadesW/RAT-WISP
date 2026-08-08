import { useMemo, useRef, useState } from 'react'
import { useSessionStore } from '../stores/useSessionStore'
import { useTabStore } from '../stores/useTabStore'
import { useT } from '../i18n'
import { ContextMenu, ContextMenuItem } from './ContextMenu'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

interface MenuState {
  x: number
  y: number
  items: ContextMenuItem[]
}

interface ModalState {
  title: string
  message?: string
  placeholder?: string
  onOk: (input: string) => void
}

interface Column {
  key: string
  labelKey: string
  width?: number
  visible: boolean
  value: (s: any) => string
  // sortValue optionally provides the raw comparable value for sorting. When
  // present and numeric, sorting uses numeric comparison — the displayed
  // string (e.g. "10" vs "2") would otherwise be compared lexicographically.
  sortValue?: (s: any) => number | string
}

const ALL_COLUMNS: Column[] = [
  { key: 'status', labelKey: 'sessionStatus', width: 40, visible: true, value: s => s.status },
  // seq is a stable number assigned at registration (stored in the DB) and is
  // never renumbered when sessions are deleted
  { key: 'seq', labelKey: 'sessionSeq', width: 40, visible: true, value: s => s.seq > 0 ? String(s.seq) : '', sortValue: s => s.seq },
  { key: 'id', labelKey: 'sessionAgentID', width: 120, visible: true, value: s => s.id },
  { key: 'external_ip', labelKey: 'sessionExtIP', width: 110, visible: true, value: s => s.external_ip },  { key: 'internal_ip', labelKey: 'sessionIntIP', width: 110, visible: true, value: s => s.internal_ip || '' },
  { key: 'hostname', labelKey: 'sessionHostname', width: 110, visible: true, value: s => s.hostname },
  { key: 'username', labelKey: 'sessionUser', width: 100, visible: true, value: s => (s.domain ? `${s.domain}\\${s.username}` : s.username) },
  { key: 'os', labelKey: 'sessionOS', width: 80, visible: true, value: s => s.os },
  // process_name is a full path on Windows; show only the file name
  { key: 'process_name', labelKey: 'sessionProcess', width: 90, visible: true, value: s => (s.process_name || '').split(/[\\/]/).pop() || '' },
  // protocol = the transport the agent used to check in (tcp/kcp/http/https)
  { key: 'protocol', labelKey: 'sessionProtocol', width: 60, visible: true, value: s => (s.protocol || '').toUpperCase() || '-' },
  { key: 'last_seen', labelKey: 'sessionLastSeen', width: 90, visible: true, value: s => s.last_seen, sortValue: s => Date.parse(s.last_seen) || 0 },
  // sleep shows a formatted interval; sort by the raw milliseconds
  { key: 'sleep', labelKey: 'sessionSleep', width: 90, visible: true, value: s => s.sleep_interval > 0 ? formatSleep(s.sleep_interval) + (s.jitter > 0 ? `(${s.jitter}%)` : '') : '-', sortValue: s => s.sleep_interval || 0 },
  { key: 'note', labelKey: 'sessionNote', width: 160, visible: true, value: s => s.note || '' },
]

// formatSleep renders a millisecond interval compactly: 200ms, 5s, 100s, 3m.
function formatSleep(ms: number): string {
  if (ms < 1000) return `${ms}ms`
  const s = ms / 1000
  if (s < 60) return s % 1 === 0 ? `${s}s` : `${s.toFixed(1)}s`
  const m = s / 60
  return m % 1 === 0 ? `${m}m` : `${m.toFixed(1)}m`
}

export function SessionTable() {
  const t = useT()
  const sessions = useSessionStore(s => s.sessions)
  const selectedId = useSessionStore(s => s.selectedId)
  const setSelected = useSessionStore(s => s.setSelected)
  const openTab = useTabStore(s => s.openTab)

  const [statusFilter, setStatusFilter] = useState('')
  const [query, setQuery] = useState('')
  const [menu, setMenu] = useState<MenuState | null>(null)
  const [sortKey, setSortKey] = useState('last_seen')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')
  const [columns, setColumns] = useState<Column[]>(ALL_COLUMNS)
  const [headerMenu, setHeaderMenu] = useState<{ x: number; y: number } | null>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)

  // Wails webviews do not implement window.prompt / window.confirm, so edits
  // and confirmations go through a small in-app modal instead.
  const [modal, setModal] = useState<ModalState | null>(null)
  const [modalInput, setModalInput] = useState('')

  const openInputModal = (title: string, initial: string, placeholder: string, onOk: (v: string) => void) => {
    setModalInput(initial)
    setModal({ title, placeholder, onOk })
  }

  const openConfirmModal = (title: string, message: string, onOk: () => void) => {
    setModal({ title, message, onOk })
  }

  const filtered = useMemo(() => {
    let list = sessions
    if (statusFilter) list = list.filter(s => s.status === statusFilter)
    const q = query.trim().toLowerCase()
    if (q) {
      list = list.filter(s =>
        s.id.toLowerCase().includes(q) ||
        s.hostname.toLowerCase().includes(q) ||
        s.username.toLowerCase().includes(q) ||
        s.external_ip.toLowerCase().includes(q) ||
        s.internal_ip.toLowerCase().includes(q),
      )
    }
    const visible = columns.filter(c => c.visible)
    const col = visible.find(c => c.key === sortKey)
    if (col) {
      list = [...list].sort((a, b) => {
        const ra = col.sortValue ? col.sortValue(a) : col.value(a)
        const rb = col.sortValue ? col.sortValue(b) : col.value(b)
        // Numeric columns (seq, sleep_interval, timestamp) compare numerically;
        // everything else compares case-insensitively as text.
        if (typeof ra === 'number' && typeof rb === 'number') {
          if (ra < rb) return sortDir === 'asc' ? -1 : 1
          if (ra > rb) return sortDir === 'asc' ? 1 : -1
          return 0
        }
        const sa = String(ra).toLowerCase()
        const sb = String(rb).toLowerCase()
        if (sa < sb) return sortDir === 'asc' ? -1 : 1
        if (sa > sb) return sortDir === 'asc' ? 1 : -1
        return 0
      })
    }
    return list
  }, [sessions, statusFilter, query, columns, sortKey, sortDir])

  const toggleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const toggleColumn = (key: string) => {
    setColumns(cols => cols.map(c => (c.key === key ? { ...c, visible: !c.visible } : c)))
  }

  const editNote = (s: { id: string; note?: string }) => {
    openInputModal(t('menuEditNote'), s.note || '', t('menuEditNote'), (note) => {
      callBackend('github.com/user/wisp/services.SessionService.UpdateSessionNote', s.id, note)
    })
  }

  const adjustSleep = (s: { id: string; sleep_interval: number; jitter: number }) => {
    const cur = s.sleep_interval > 0 ? s.sleep_interval : 5000
    const curJ = s.jitter > 0 ? s.jitter : 0
    openInputModal(t('sessionSleepPrompt'), curJ > 0 ? `${cur} ${curJ}` : String(cur), '', (val) => {
      const parts = val.trim().split(/\s+/)
      const sleep = Number(parts[0])
      if (!parts[0] || isNaN(sleep)) return
      const jitter = parts.length > 1 ? Number(parts[1]) : 0
      if (isNaN(jitter)) return
      const args = JSON.stringify({ sleep: String(Math.round(sleep)), jitter: String(Math.round(jitter)) })
      callBackend('github.com/user/wisp/services.SessionService.SendCommand', s.id, 'sleep', args)
    })
  }

  const setStatus = (s: { id: string; status: string }) => {
    const next = s.status === 'alive' ? 'dead' : 'alive'
    callBackend('github.com/user/wisp/services.SessionService.SetSessionStatus', s.id, next)
  }

  const removeSession = (s: { id: string }) => {
    openConfirmModal(t('menuConfirmDelete') + s.id, t('menuConfirmDeleteHint'), () => {
      callBackend('github.com/user/wisp/services.SessionService.RemoveSession', s.id)
    })
  }

  const killAgent = (s: { id: string }) => {
    openConfirmModal(t('menuKillAgentConfirm'), '', () => {
      callBackend('github.com/user/wisp/services.SessionService.ClientKill', s.id)
    })
  }

  const hostAction = (s: { id: string }, action: 'reboot' | 'shutdown' | 'logoff' | 'lock') => {
    const labels: Record<string, string> = {
      reboot: t('menuHostReboot'),
      shutdown: t('menuHostShutdown'),
      logoff: t('menuHostLogoff'),
      lock: t('menuHostLock'),
    }
    const methods: Record<string, string> = {
      reboot: 'HostReboot',
      shutdown: 'HostShutdown',
      logoff: 'HostLogoff',
      lock: 'HostLock',
    }
    openConfirmModal(labels[action], t('menuHostActionConfirm').replace('{action}', labels[action]), () => {
      callBackend(`github.com/user/wisp/services.SessionService.${methods[action]}`, s.id)
    })
  }

  const openMenu = (e: React.MouseEvent, s: { id: string; status: string; hostname?: string; sleep_interval: number; jitter: number }) => {
    e.preventDefault()
    setSelected(s.id)
    setMenu({
      x: e.clientX,
      y: e.clientY,
      items: [
        {
          label: t('menuOpenShell'),
          onClick: () => {
            setSelected(s.id)
            openTab({ kind: 'shell', sessionId: s.id, title: `${s.hostname} — ${t('menuOpenShell')}`, closable: true })
          },
        },
        {
          label: t('menuOpenFiles'),
          onClick: () => openTab({ kind: 'files', sessionId: s.id, title: `${s.hostname} — ${t('menuOpenFiles')}`, closable: true }),
        },
        {
          label: t('menuRemoteDesktop'),
          onClick: () => {
            callBackend('github.com/user/wisp/services.SessionService.OpenRemoteDesktopWindow', s.id)
          },
        },
        {
          label: t('menuRemoteControl'),
          onClick: () => {
            callBackend('github.com/user/wisp/services.SessionService.OpenRemoteControlWindow', s.id)
          },
        },
        {
          label: t('menuScreenshot'),
          onClick: () => {
            callBackend('github.com/user/wisp/services.SessionService.OpenScreenshotWindow', s.id)
          },
        },
        { label: t('menuEditNote'), onClick: () => editNote(s) },
        { label: t('menuAdjustSleep'), onClick: () => adjustSleep(s) },
        {
          label: t('menuClientManagement'),
          submenu: [
            { label: t('menuKillAgent'), danger: true, onClick: () => killAgent(s) },
          ],
        },
        {
          label: t('menuComputerManagement'),
          submenu: [
            { label: t('menuHostReboot'), onClick: () => hostAction(s, 'reboot') },
            { label: t('menuHostShutdown'), onClick: () => hostAction(s, 'shutdown') },
            { separator: true },
            { label: t('menuHostLogoff'), onClick: () => hostAction(s, 'logoff') },
            { label: t('menuHostLock'), onClick: () => hostAction(s, 'lock') },
          ],
        },
        { separator: true },
        {
          label: s.status === 'alive' ? t('menuMarkDead') : t('menuMarkAlive'),
          onClick: () => setStatus(s),
        },
        { label: t('menuDelete'), danger: true, onClick: () => removeSession(s) },
      ],
    })
  }

  const visibleCols = columns.filter(c => c.visible)

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', gap: 8, padding: '6px 8px', alignItems: 'center' }}>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">{t('sessionAll')}</option>
          <option value="alive">{t('sessionAlive')}</option>
          <option value="dead">{t('sessionDead')}</option>
        </select>
        <input
          className="filter-input"
          placeholder={t('sessionFilterPlaceholder')}
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
        <button className="toolbar-btn" onClick={() => setSearchOpen(o => !o)} title={t('sessionSearch')}>🔍</button>
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 12 }}>
          {filtered.length} / {sessions.length}
        </span>
      </div>
      {searchOpen && (
        <div className="console-search" style={{ padding: '4px 8px' }}>
          <input
            ref={searchRef}
            className="filter-input"
            style={{ flex: 1 }}
            autoFocus
            placeholder={t('sessionQuickFilter')}
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
          <button className="toolbar-btn" onClick={() => { setSearchOpen(false); setQuery('') }}>✕</button>
        </div>
      )}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="session-table">
          <thead>
            <tr>
              {visibleCols.map(c => (
                <th
                  key={c.key}
                  style={{ width: c.width, cursor: 'pointer' }}
                  onClick={() => toggleSort(c.key)}
                  onContextMenu={e => {
                    e.preventDefault()
                    setHeaderMenu({ x: e.clientX, y: e.clientY })
                  }}
                  title={t('sessionSortHint')}
                >
                  {t(c.labelKey)}
                  {sortKey === c.key && <span style={{ marginLeft: 4 }}>{sortDir === 'asc' ? '↑' : '↓'}</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={visibleCols.length} style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)' }}>
                  {t('sessionEmpty')}
                </td>
              </tr>
            ) : (
              filtered.map(s => (
                <tr
                  key={s.id}
                  className={s.id === selectedId ? 'selected' : ''}
                  onClick={() => setSelected(s.id)}
                  onContextMenu={e => openMenu(e, s)}
                >
                  {visibleCols.map(c => {
                    const v = c.value(s)
                    if (c.key === 'status') return <td key={c.key}><span className={`status-dot ${v}`} /></td>
                    return (
                      <td
                        key={c.key}
                        className={c.key === 'seq' || c.key === 'id' || c.key === 'external_ip' || c.key === 'internal_ip' || c.key === 'last_seen' ? 'mono' : ''}
                        title={c.key === 'note' || c.key === 'sleep' ? t('sessionNoteHint') : undefined}
                        onDoubleClick={
                          c.key === 'note'
                            ? e => {
                                e.preventDefault()
                                editNote(s)
                              }
                            : c.key === 'sleep'
                              ? e => {
                                  e.preventDefault()
                                  adjustSleep(s)
                                }
                              : undefined
                        }
                      >
                        {v}
                      </td>
                    )
                  })}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
      {headerMenu && (
        <ContextMenu
          x={headerMenu.x}
          y={headerMenu.y}
          items={columns.map(col => ({
            label: `${col.visible ? '✓ ' : ''}${t(col.labelKey)}`,
            keepOpen: true,
            onClick: () => toggleColumn(col.key),
          }))}
          onClose={() => setHeaderMenu(null)}
        />
      )}
      {modal && (
        <div className="dialog-overlay" onClick={() => setModal(null)}>
          <div className="dialog" onClick={e => e.stopPropagation()}>
            <h2>{modal.title}</h2>
            {modal.message && (
              <p style={{ marginBottom: 12, color: 'var(--text-muted)', fontSize: 13 }}>{modal.message}</p>
            )}
            {modal.placeholder !== undefined && (
              <input
                className="filter-input"
                style={{ width: '100%', marginBottom: 12 }}
                value={modalInput}
                placeholder={modal.placeholder}
                onChange={e => setModalInput(e.target.value)}
                autoFocus
                onKeyDown={e => {
                  if (e.key === 'Enter') {
                    setModal(null)
                    modal.onOk(modalInput)
                  }
                }}
              />
            )}
            <div className="dialog-actions">
              <button onClick={() => setModal(null)}>{t('fsCancel')}</button>
              <button
                className="btn-primary"
                onClick={() => {
                  setModal(null)
                  modal.onOk(modal.placeholder !== undefined ? modalInput : '')
                }}
              >
                {t('dlgOk')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
