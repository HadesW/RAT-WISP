import { useEffect, useRef, useState } from 'react'
import { callByName } from '../wails'
import { useSessionStore } from '../stores/useSessionStore'
import { useListenerStore } from '../stores/useListenerStore'
import { useTabStore } from '../stores/useTabStore'
import { useI18nStore, useT, type Lang } from '../i18n'
import { SessionTable } from '../components/SessionTable'
import { Console } from '../components/Console'
import { ShellView } from '../components/ShellView'
import { ListenersPanel } from '../components/ListenersPanel'
import { FileManager } from '../components/FileManager'
import { LogView } from '../components/LogView'
import { TaskView } from '../components/TaskView'
import { FileTransferView } from '../components/FileTransferView'
import { FileServerPanel } from '../components/FileServerPanel'
import { PayloadDialog } from '../components/PayloadDialog'

export function DashboardPage() {
  const t = useT()
  const lang = useI18nStore(s => s.lang)
  const setLang = useI18nStore(s => s.setLang)

  const sessions = useSessionStore(s => s.sessions)
  const setSessions = useSessionStore(s => s.setSessions)
  const setListeners = useListenerStore(s => s.setListeners)
  const listeners = useListenerStore(s => s.listeners)

  const tabs = useTabStore(s => s.tabs)
  const activeId = useTabStore(s => s.activeId)
  const openTab = useTabStore(s => s.openTab)
  const closeTab = useTabStore(s => s.closeTab)
  const setActive = useTabStore(s => s.setActive)

  // Closing a tab also terminates the agent-side feature it represents
  const closeTabWithCleanup = (id: string) => {
    const tb = tabs.find(x => x.id === id)
    if (tb?.kind === 'shell' && tb.sessionId) {
      callByName('github.com/user/wisp/services.SessionService.IshellClose', tb.sessionId)
    }
    closeTab(id)
  }

  const [showPayload, setShowPayload] = useState(false)

  // Draggable splitter between the session table (top) and the tab area
  // (bottom). Clamped so neither pane can take over the whole window.
  const [splitPct, setSplitPct] = useState(48)
  const layoutRef = useRef<HTMLDivElement>(null)
  const dragRef = useRef<{ startY: number; startPct: number } | null>(null)

  const onSplitterDown = (e: React.MouseEvent) => {
    e.preventDefault()
    dragRef.current = { startY: e.clientY, startPct: splitPct }
    const onMove = (ev: MouseEvent) => {
      const el = layoutRef.current
      if (!el || !dragRef.current) return
      const rect = el.getBoundingClientRect()
      if (rect.height <= 0) return
      const pct = dragRef.current.startPct + ((ev.clientY - dragRef.current.startY) / rect.height) * 100
      setSplitPct(Math.min(70, Math.max(20, pct)))
    }
    const onUp = () => {
      dragRef.current = null
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('mouseup', onUp)
    }
    window.addEventListener('mousemove', onMove)
    window.addEventListener('mouseup', onUp)
  }

  const refresh = async () => {
    try {
      const data = await callByName('github.com/user/wisp/services.SessionService.List')
      if (data) setSessions(data)
    } catch { /* ignore */ }
    try {
      const data = await callByName('github.com/user/wisp/services.ListenerService.List')
      if (data) setListeners(data)
    } catch { /* ignore */ }
  }

  useEffect(() => {
    useSessionStore.getState().initEventListeners()
    useListenerStore.getState().initEventListeners()
    refresh()
    const t = setInterval(refresh, 5000)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const active = tabs.find(t => t.id === activeId) || tabs[0]
  // Keep the selected session in sync with the active console/files tab
  useEffect(() => {
    if (active?.sessionId) {
      useSessionStore.setState({ selectedId: active.sessionId })
    }
  }, [active?.id, active?.sessionId])

  const aliveSessions = sessions.filter(s => s.status === 'alive').length
  const runningListeners = listeners.filter(l => l.status === 'running').length

  return (
    <div className="app-layout">
      <div className="toolbar">
        <button className="toolbar-btn primary" onClick={refresh}>Refresh</button>
        <button className="toolbar-btn" onClick={() => openTab({ kind: 'listeners', title: t('tabListeners'), closable: true })}>
          {t('toolbarListeners')}
        </button>
        <button className="toolbar-btn" onClick={() => openTab({ kind: 'tasks', title: t('toolbarTasks'), closable: true })}>
          {t('toolbarTasks')}
        </button>
        <button className="toolbar-btn" onClick={() => openTab({ kind: 'transfers', title: t('tabTransfers'), closable: true })}>
          {t('toolbarTransfers')}
        </button>
        <button className="toolbar-btn" onClick={() => openTab({ kind: 'fileserver', title: t('tabFileServer'), closable: true })}>
          {t('toolbarFileServer')}
        </button>
        <button className="toolbar-btn" onClick={() => setShowPayload(true)}>{t('toolbarPayload')}</button>
        <div className="spacer" />
        <select
          className="lang-select"
          value={lang}
          onChange={e => setLang(e.target.value as Lang)}
          title="Language / 语言"
        >
          <option value="zh">中文</option>
          <option value="en">English</option>
        </select>
      </div>
      <div ref={layoutRef} style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flex: `0 0 ${splitPct}%`, overflow: 'hidden' }}>
          <SessionTable />
        </div>
        <div
          className="splitter"
          onMouseDown={onSplitterDown}
          title="Drag to resize"
        />
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minHeight: 0 }}>
          <div className="tab-bar">
            {tabs.map(t => (
              <span
                key={t.id}
                className={`tab${t.id === activeId ? ' active' : ''}`}
                onClick={() => setActive(t.id)}
              >
                <span className="tab-label">{t.title}</span>
                {t.closable && (
                  <span
                    className="tab-close"
                    onClick={e => { e.stopPropagation(); closeTabWithCleanup(t.id) }}
                    title="Close tab"
                  >
                    ×
                  </span>
                )}
              </span>
            ))}
          </div>
          <div style={{ flex: 1, overflow: 'hidden', minHeight: 0 }}>
            {active.kind === 'log' && <LogView />}
            {active.kind === 'listeners' && <ListenersPanel />}
            {active.kind === 'console' && <Console />}
            {active.kind === 'shell' && active.sessionId && <ShellView sessionId={active.sessionId} />}
            {active.kind === 'files' && <FileManager sessionId={active.sessionId || null} />}
            {active.kind === 'tasks' && <TaskView />}
            {active.kind === 'transfers' && <FileTransferView />}
            {active.kind === 'fileserver' && <FileServerPanel />}
          </div>
        </div>
      </div>
      <div className="statusbar">
        <div><span className={`dot ${runningListeners > 0 ? 'green' : 'red'}`} />Listeners: {runningListeners} active</div>
        <div>Sessions: {sessions.length} ({aliveSessions} online)</div>
        <div className="spacer" />
        <div>Wisp v1.0.0</div>
      </div>
      {showPayload && <PayloadDialog onClose={() => setShowPayload(false)} />}
    </div>
  )
}
