import { DashboardPage } from './pages/DashboardPage'
import { RemoteDesktopView } from './components/RemoteDesktopView'
import { RemoteControlView } from './components/RemoteControlView'
import { ScreenshotView } from './components/ScreenshotView'

export default function App() {
  // The remote desktop and remote control features render in their own OS
  // windows, opened by the backend with "?view=rdp|rc&session=<id>". Detect
  // them here so those windows only mount the dedicated view.
  const params = new URLSearchParams(window.location.search)
  const view = params.get('view')
  const session = params.get('session')
  if (view === 'rdp' && session) {
    return <RemoteDesktopView sessionId={session} standalone />
  }
  if (view === 'rc' && session) {
    return <RemoteControlView sessionId={session} standalone />
  }
  if (view === 'shot' && session) {
    return <ScreenshotView sessionId={session} />
  }
  return <DashboardPage />
}
