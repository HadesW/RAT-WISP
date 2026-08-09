import { create } from 'zustand'

let eventsModule: any = null
async function getEvents() {
  if (!eventsModule) {
    try {
      eventsModule = await import('@wailsio/runtime')
    } catch { /* not in Wails context */ }
  }
  return eventsModule?.Events
}

// Wails delivers the emitted value directly as `event.data` (single-arg Emit),
// not wrapped in an array. Array.isArray keeps string payloads intact
// (string[0] would return the first character).
function unwrapEventData(event: any): any {
  const d = event?.data
  return Array.isArray(d) ? d[0] : d
}

export interface SessionInfo {
  id: string
  seq: number
  listener_id: string
  protocol: string
  external_ip: string
  internal_ip: string
  hostname: string
  username: string
  domain: string
  os: string
  arch: string
  pid: number
  process_name: string
  is_elevated: boolean
  sleep_interval: number
  jitter: number
  first_seen: string
  last_seen: string
  status: string
  note: string
}

export interface ConsoleEntry {
  type: 'input' | 'output' | 'info' | 'error'
  content: string
  timestamp: string
}

// ShellLine is one line of an interactive shell tab (ShellView). It lives in
// the store so switching tabs (which unmounts the view) does not lose the
// shell type or its output history.
export interface ShellLine {
  type: 'input' | 'output' | 'info' | 'error'
  content: string
  time: string
}

interface SessionState {
  sessions: SessionInfo[]
  selectedId: string | null
  console: Record<string, ConsoleEntry[]>
  consoleHistory: Record<string, string[]> // per-session command history
  consoleDraft: Record<string, string>     // per-session unsent input
  ishell: Record<string, string | null>    // per-session interactive shell name
  ishellLines: Record<string, ShellLine[]> // per-session shell output history
  setSessions: (sessions: SessionInfo[]) => void
  setSelected: (id: string | null) => void
  addConsoleEntry: (sessionId: string, entry: ConsoleEntry) => void
  pushHistory: (sessionId: string, cmd: string) => void
  setDraft: (sessionId: string, text: string) => void
  clearConsole: (sessionId: string) => void
  setIshell: (sessionId: string, shell: string | null) => void
  setIshellLines: (sessionId: string, lines: ShellLine[]) => void
  appendIshellLine: (sessionId: string, line: ShellLine) => void
  initEventListeners: () => void
}

export const useSessionStore = create<SessionState>((set, get) => ({
  sessions: [],
  selectedId: null,
  console: {},
  consoleHistory: {},
  consoleDraft: {},
  ishell: {},
  ishellLines: {},

  setSessions: (sessions) => set({ sessions }),
  setSelected: (id) => set({ selectedId: id }),

  pushHistory: (sessionId, cmd) => set((state) => ({
    consoleHistory: {
      ...state.consoleHistory,
      [sessionId]: [...(state.consoleHistory[sessionId] || []), cmd],
    },
  })),

  setDraft: (sessionId, text) => set((state) => ({
    consoleDraft: { ...state.consoleDraft, [sessionId]: text },
  })),

  clearConsole: (sessionId) => set((state) => ({
    console: { ...state.console, [sessionId]: [] },
  })),

  setIshell: (sessionId, shell) => set((state) => ({
    ishell: { ...state.ishell, [sessionId]: shell },
  })),

  setIshellLines: (sessionId, lines) => set((state) => ({
    ishellLines: { ...state.ishellLines, [sessionId]: lines },
  })),

  appendIshellLine: (sessionId, line) => set((state) => ({
    ishellLines: {
      ...state.ishellLines,
      [sessionId]: [...(state.ishellLines[sessionId] || []), line],
    },
  })),

  addConsoleEntry: (sessionId, entry) => set((state) => {
    const next = [...(state.console[sessionId] || []), entry]
    // Bound the in-memory console per session (the view already truncates)
    if (next.length > 5000) next.splice(0, next.length - 5000)
    return { console: { ...state.console, [sessionId]: next } }
  }),

  initEventListeners: () => {
    getEvents().then(Events => {
      if (!Events) return

      Events.On('session:new', (event: { data: SessionInfo | SessionInfo[] }) => {
        const session = unwrapEventData(event) as SessionInfo
        if (!session) return
        set((state) => ({
          sessions: [session, ...state.sessions.filter(s => s.id !== session.id)],
        }))
      })

      Events.On('session:dead', (event: { data: string | string[] }) => {
        const id = unwrapEventData(event) as string
        set((state) => ({
          sessions: state.sessions.map(s =>
            s.id === id ? { ...s, status: 'dead' } : s
          ),
        }))
      })

      Events.On('session:removed', (event: { data: string | string[] }) => {
        const id = unwrapEventData(event) as string
        set((state) => ({
          sessions: state.sessions.filter(s => s.id !== id),
        }))
      })
    })
  },
}))

// defaultShellForSession returns the interactive shell that should be opened by
// default for a session: cmd.exe on Windows, bash everywhere else.
export function defaultShellForSession(sessionId: string | null | undefined): string {
  const s = sessionId ? useSessionStore.getState().sessions.find(x => x.id === sessionId) : undefined
  const os = (s?.os || '').toLowerCase()
  return os.includes('windows') ? 'cmd' : 'bash'
}
