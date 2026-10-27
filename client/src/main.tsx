import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@xterm/xterm/css/xterm.css'
import './index.css'
import App from './App.tsx'
import RemoteControl from './RemoteControl.tsx'
import { ErrorBoundary } from './ErrorBoundary.tsx'

const rc = window.location.pathname.match(/^\/rc\/([0-9a-fA-F]+)/)
if (rc) {
  const q = new URLSearchParams(location.search).get('token')
  if (q) localStorage.setItem('wisp_token', q)
}
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      {rc ? <RemoteControl sessionId={rc[1]} /> : <App />}
    </ErrorBoundary>
  </StrictMode>,
)
