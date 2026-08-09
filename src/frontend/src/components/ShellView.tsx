import { useCallback, useEffect, useRef, useState } from 'react'
import { defaultShellForSession, useSessionStore, type ShellLine } from '../stores/useSessionStore'

async function callBackend(method: string, ...args: unknown[]) {
  const runtime = await import('@wailsio/runtime')
  return runtime.Call.ByName(method, ...args)
}

const POLL_MS = 400
const TIMEOUT_MS = 30000

// ShellView is a self-contained interactive shell tab. Its state (shell type,
// output history) lives in the session store so switching away and back to the
// tab — which unmounts and remounts this component — keeps the same shell type
// and reconnects to the existing agent-side session instead of resetting it.
export function ShellView({ sessionId }: { sessionId: string }) {
  // Restore the previously chosen shell type (e.g. powershell) if one is
  // already open for this session; otherwise fall back to the per-platform
  // default (cmd on Windows, bash elsewhere).
  const savedShell = useSessionStore(s => s.ishell[sessionId])
  const savedLines = useSessionStore(s => s.ishellLines[sessionId])
  const setIshell = useSessionStore(s => s.setIshell)
  const setIshellLines = useSessionStore(s => s.setIshellLines)
  const appendIshellLine = useSessionStore(s => s.appendIshellLine)

  const [lines, setLines] = useState<ShellLine[]>(savedLines || [])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [shell, setShell] = useState(() => savedShell || defaultShellForSession(sessionId))

  const outputRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const historyRef = useRef<string[]>([])
  const histIdxRef = useRef(-1)

  const push = useCallback((type: ShellLine['type'], content: string) => {
    const line: ShellLine = { type, content, time: new Date().toLocaleTimeString() }
    setLines(prev => [...prev, line])
    appendIshellLine(sessionId, line)
  }, [sessionId, appendIshellLine])

  useEffect(() => {
    if (outputRef.current) outputRef.current.scrollTop = outputRef.current.scrollHeight
  }, [lines])

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  // The input is disabled while busy, so calling focus() right after
  // setBusy(false) has no effect (React hasn't re-rendered yet). Focus from an
  // effect instead, which runs after the DOM update that re-enables the input.
  useEffect(() => {
    if (!busy) inputRef.current?.focus()
  }, [busy])

  const pollTask = useCallback(async (taskID: string, timeout = TIMEOUT_MS): Promise<any> => {
    const deadline = Date.now() + timeout
    while (Date.now() < deadline) {
      await new Promise(r => setTimeout(r, POLL_MS))
      const task = await callBackend('github.com/user/wisp/services.SessionService.GetTask', taskID)
      if (task && (task.status === 'completed' || task.status === 'failed')) return task
    }
    throw new Error('command timed out')
  }, [])

  // Open (or reopen) the interactive shell for a shell type
  const openShell = useCallback(async (shellType: string, reopen = false) => {
    if (!sessionId) return
    if (reopen) {
      try {
        const t = await callBackend('github.com/user/wisp/services.SessionService.IshellClose', sessionId)
        await pollTask(t)
      } catch { /* ignore */ }
    }
    push('info', `Opening ${shellType} on target...`)
    setBusy(true)
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.IshellOpen', sessionId, shellType)
      const task = await pollTask(taskID)
      setIshell(sessionId, shellType)
      const out = task.result || ''
      const trimmed = out.replace(/^\s*interactive shell started[^\n]*\n?/, '')
      if (trimmed.trim()) push('output', trimmed)
      else push('info', `${shellType} shell is ready. Type commands below (exit to close).`)
    } catch (e) {
      push('error', String(e))
    } finally {
      setBusy(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId])

  // Open the shell when the tab appears — unless a shell for this session is
  // already open (store.ishell set), in which case the agent-side process is
  // still alive and we simply reconnect instead of resetting it.
  useEffect(() => {
    if (savedShell) {
      push('info', `Reconnected to existing ${savedShell} shell.`)
      return
    }
    openShell(shell)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const switchShell = (next: string) => {
    setShell(next)
    openShell(next, true) // reopen with the new shell type
  }

  const closeShell = async () => {
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.IshellClose', sessionId)
      await pollTask(taskID)
    } catch { /* ignore */ }
    push('info', 'shell closed')
    setIshell(sessionId, null)
    setIshellLines(sessionId, [])
    setBusy(false)
  }

  const send = async () => {
    const line = input.trim()
    if (!line || busy) return
    setInput('')
    historyRef.current.push(line)
    histIdxRef.current = -1
    push('input', line)

    if (line === 'exit' || line === 'ishell exit') {
      await closeShell()
      return
    }

    setBusy(true)
    try {
      const taskID = await callBackend('github.com/user/wisp/services.SessionService.IshellRun', sessionId, line)
      const task = await pollTask(taskID)
      const out = (task.result || '').trim()
      if (out) push(task.status === 'failed' ? 'error' : 'output', out)
    } catch (e) {
      push('error', String(e))
    } finally {
      setBusy(false)
    }
  }

  const handleKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      send()
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      const h = historyRef.current
      if (h.length === 0) return
      const idx = histIdxRef.current < h.length - 1 ? histIdxRef.current + 1 : histIdxRef.current
      histIdxRef.current = idx
      setInput(h[h.length - 1 - idx])
    } else if (e.key === 'ArrowDown') {
      e.preventDefault()
      const h = historyRef.current
      if (histIdxRef.current > 0) {
        histIdxRef.current -= 1
        setInput(h[h.length - 1 - histIdxRef.current])
      } else {
        histIdxRef.current = -1
        setInput('')
      }
    }
  }

  return (
    <div className="console-wrapper" onClick={() => inputRef.current?.focus()}>
      <div className="shell-header" onClick={e => e.stopPropagation()}>
        <select
          className="filter-select"
          value={shell}
          onChange={e => switchShell(e.target.value)}
          title="Shell type (switching reopens the shell)"
        >
          <option value="cmd">cmd</option>
          <option value="powershell">PowerShell</option>
          <option value="bash">bash</option>
        </select>
        <span className="mono">{sessionId}</span>
        {busy && <span className="shell-busy">… waiting for agent</span>}
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: 11 }}>
          {shell} interactive · exit to close
        </span>
      </div>
      <div className="console-output" ref={outputRef}>
        {lines.length === 0 ? (
          <div style={{ padding: 12, color: 'var(--text-muted)' }}>Opening interactive shell...</div>
        ) : (
          lines.map((l, i) => (
            <div key={i} className="console-line">
              <span className="time">[{l.time}]</span>
              {l.type === 'input' ? (
                <><span className="prompt">PS&gt; </span><span>{l.content}</span></>
              ) : l.type === 'error' ? (
                <span className="error">{l.content}</span>
              ) : l.type === 'info' ? (
                <span className="info">{l.content}</span>
              ) : (
                <span className="output">{l.content}</span>
              )}
            </div>
          ))
        )}
      </div>
      <div className="console-input">
        <span className="prompt-symbol ishell">PS&gt;</span>
        <input
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Type a command (cmd commands work; exit to close)..."
          disabled={busy}
          autoFocus
        />
      </div>
    </div>
  )
}
