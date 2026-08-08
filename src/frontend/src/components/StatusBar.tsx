import { useSessionStore } from '../stores/useSessionStore'
import { useListenerStore } from '../stores/useListenerStore'

export function StatusBar() {
  const sessions = useSessionStore(s => s.sessions)
  const listeners = useListenerStore(s => s.listeners)

  const aliveSessions = sessions.filter(s => s.status === 'alive').length
  const runningListeners = listeners.filter(l => l.status === 'running').length

  return (
    <div className="statusbar">
      <div>
        <span className={`dot ${runningListeners > 0 ? 'green' : 'red'}`} />
        Listeners: {runningListeners} active
      </div>
      <div>
        Sessions: {sessions.length} ({aliveSessions} online)
      </div>
      <div className="spacer" />
      <div>Wisp v1.0.0</div>
    </div>
  )
}
