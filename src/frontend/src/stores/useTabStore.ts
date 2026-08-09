import { create } from 'zustand'

export type TabKind = 'log' | 'listeners' | 'console' | 'shell' | 'files' | 'tasks' | 'transfers' | 'fileserver' | 'sysinfo' | 'processes'

export interface Tab {
  id: string
  kind: TabKind
  title: string
  sessionId?: string
  closable: boolean
}

interface TabState {
  tabs: Tab[]
  activeId: string
  openTab: (tab: Omit<Tab, 'id'> & { id?: string }) => void
  closeTab: (id: string) => void
  setActive: (id: string) => void
}

function defaultId(kind: TabKind, sessionId?: string): string {
  if (kind === 'console' || kind === 'shell' || kind === 'files' || kind === 'sysinfo' || kind === 'processes') return `${kind}:${sessionId}`
  return kind
}

function buildTab(tab: Omit<Tab, 'id'> & { id?: string }): Tab {
  return { ...tab, id: tab.id || defaultId(tab.kind, tab.sessionId) }
}

export const useTabStore = create<TabState>((set, get) => ({
  // Log and Console are permanent tabs; Console is active by default so the
  // operator can drive agents from `shell <agentid>` right away.
  tabs: [
    { id: 'log', kind: 'log', title: 'Log', closable: false },
    { id: 'console', kind: 'console', title: 'Console', closable: false },
  ],
  activeId: 'console',

  openTab: tab => {
    const t = buildTab(tab)
    const exists = get().tabs.find(x => x.id === t.id)
    if (exists) {
      set({ activeId: t.id })
      return
    }
    set(state => ({ tabs: [...state.tabs, t], activeId: t.id }))
  },

  closeTab: id => {
    const { tabs, activeId } = get()
    const idx = tabs.findIndex(x => x.id === id)
    if (idx === -1 || !tabs[idx].closable) return

    const next = tabs.filter(x => x.id !== id)
    let nextActive = activeId
    if (activeId === id) {
      // Activate the tab to the left, falling back to the last remaining
      const fallback = next[Math.max(0, idx - 1)] || next[0]
      nextActive = fallback ? fallback.id : 'log'
    }
    set({ tabs: next, activeId: nextActive })
  },

  setActive: id => set({ activeId: id }),
}))
