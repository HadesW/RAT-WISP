import { useState } from 'react'
import { useListenerStore } from '../stores/useListenerStore'
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

interface MenuState {
  x: number
  y: number
  items: ContextMenuItem[]
}

export function ListenersPanel() {
  const t = useT()
  const listeners = useListenerStore(s => s.listeners)
  const setListeners = useListenerStore(s => s.setListeners)
  const [showDialog, setShowDialog] = useState(false)
  const [menu, setMenu] = useState<MenuState | null>(null)

  const refresh = () => {
    callBackend('github.com/user/wisp/services.ListenerService.List').then((data) => {
      if (data) setListeners(data as any)
    })
  }

  const startListener = (id: string) => {
    callBackend('github.com/user/wisp/services.ListenerService.Start', id).then(() => refresh())
  }

  const stopListener = (id: string) => {
    callBackend('github.com/user/wisp/services.ListenerService.Stop', id).then(() => refresh())
  }

  const deleteListener = (id: string) => {
    callBackend('github.com/user/wisp/services.ListenerService.Delete', id).then(() => refresh())
  }

  return (
    <div style={{ padding: 12, height: '100%', overflow: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 12 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600 }}>{t('tabListeners')}</h3>
        <div className="spacer" />
        <button className="toolbar-btn primary" onClick={() => setShowDialog(true)}>
          + {t('listenerNew')}
        </button>
      </div>

      <table className="session-table">
        <thead>
          <tr>
            <th>{t('listenerName')}</th>
            <th>{t('listenerProtocol')}</th>
            <th>{t('listenerHost')}</th>
            <th>{t('listenerBind')}</th>
            <th>{t('listenerTLS')}</th>
            <th>{t('listenerStatus')}</th>
            <th style={{ width: 130 }}>{t('listenerActions')}</th>
          </tr>
        </thead>
        <tbody>
          {listeners.length === 0 ? (
            <tr>
              <td colSpan={7} style={{ textAlign: 'center', padding: 16, color: 'var(--text-muted)' }}>
                {t('listenerEmpty')}
              </td>
            </tr>
          ) : (
            listeners.map(l => (
              <tr key={l.id} onContextMenu={e => {
                e.preventDefault()
                setMenu({
                  x: e.clientX,
                  y: e.clientY,
                  items: [
                    {
                      label: t('listenerStart'),
                      disabled: l.status === 'running',
                      onClick: () => startListener(l.id),
                    },
                    {
                      label: t('listenerStop'),
                      disabled: l.status !== 'running',
                      onClick: () => stopListener(l.id),
                    },
                    { separator: true },
                    {
                      label: t('listenerDelete'),
                      danger: true,
                      disabled: l.status === 'running',
                      onClick: () => deleteListener(l.id),
                    },
                  ],
                })
              }}>
                <td>{l.name}</td>
                <td>{l.protocol.toUpperCase()}</td>
                <td className="mono">{l.host || '-'}</td>
                <td className="mono">{l.bind_host}:{l.bind_port}</td>
                <td>{l.use_tls ? 'Yes' : 'No'}</td>
                <td>
                  <span style={{ color: l.status === 'running' ? 'var(--ok)' : 'var(--text-muted)' }}>
                    {l.status}
                  </span>
                </td>
                <td>
                  <div className="listener-actions">
                    <button
                      className="toolbar-btn"
                      disabled={l.status === 'running'}
                      onClick={() => startListener(l.id)}
                      title="Start"
                    >
                      ▶
                    </button>
                    <button
                      className="toolbar-btn"
                      disabled={l.status !== 'running'}
                      onClick={() => stopListener(l.id)}
                      title="Stop"
                    >
                      ⏹
                    </button>
                    <button
                      className="toolbar-btn"
                      disabled={l.status === 'running'}
                      onClick={() => deleteListener(l.id)}
                      title="Delete"
                    >
                      ✕
                    </button>
                  </div>
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>

      {showDialog && <AddListenerDialog onClose={() => { setShowDialog(false); refresh() }} />}
      {menu && <ContextMenu x={menu.x} y={menu.y} items={menu.items} onClose={() => setMenu(null)} />}
    </div>
  )
}

// Default ports per listener protocol, using the common port where one exists
// (HTTP 80 / HTTPS 443) and distinct C2 defaults for TCP vs KCP so the two
// transports are never confused when setting up multiple listeners.
const PROTOCOL_DEFAULT_PORTS: Record<string, string> = {
  tcp: '4444',
  kcp: '5555',
  quic: '6666',
  http: '80',
  https: '443',
}

function AddListenerDialog({ onClose }: { onClose: () => void }) {
  const t = useT()
  const [name, setName] = useState('')
  const [protocol, setProtocol] = useState('tcp')
  const [host, setHost] = useState('')
  const [bind, setBind] = useState('0.0.0.0')
  const [port, setPort] = useState(PROTOCOL_DEFAULT_PORTS.tcp)
  const [useTLS, setUseTLS] = useState(false)
  const [psk, setPSK] = useState('')
  // Malleable traffic profile: path (display) + raw JSON content baked at
  // creation time (Cobalt-Strike style "pick profile, create, done").
  const [profilePath, setProfilePath] = useState('')
  const [profile, setProfile] = useState('')

  // https implicitly enables TLS
  const isHTTPS = protocol === 'https'
  const handleProtocolChange = (p: string) => {
    setProtocol(p)
    // Switch the port to the protocol's default. Choosing a protocol implies
    // its standard port (e.g. HTTPS → 443); the user can still edit it.
    setPort(PROTOCOL_DEFAULT_PORTS[p] ?? PROTOCOL_DEFAULT_PORTS.tcp)
    if (p === 'https') setUseTLS(true)
  }

  const pickProfile = async () => {
    try {
      const { Dialogs } = await import('@wailsio/runtime')
      const path = await Dialogs.OpenFile({
        CanChooseFiles: true,
        CanChooseDirectories: false,
        Title: t('listenerProfilePick'),
        Filters: [{ DisplayName: 'Malleable Profile (*.json)', Pattern: '*.json' }],
      })
      if (!path) return
      const content = await callBackend('github.com/user/wisp/services.SessionService.ReadLocalFile', path)
      if (content !== null && content !== undefined) {
        setProfilePath(String(path))
        setProfile(String(content))
      } else {
        setProfilePath('')
        setProfile('')
      }
    } catch (e) {
      console.warn('pick profile failed:', e)
    }
  }

  const handleCreate = () => {
    callBackend(
      'github.com/user/wisp/services.ListenerService.Create',
      name,
      protocol,
      host,
      bind,
      parseInt(port),
      isHTTPS ? true : useTLS,
      psk,
      profile,
    ).then(() => onClose())
  }

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog" onClick={e => e.stopPropagation()}>
        <h2>{t('listenerNew')}</h2>
        <label>{t('dlgName')}</label>
        <input value={name} onChange={e => setName(e.target.value)} placeholder="HTTP-01" />
        <label>{t('dlgProtocol')}</label>
        <select value={protocol} onChange={e => handleProtocolChange(e.target.value)}>
          <option value="tcp">TCP</option>
          <option value="http">HTTP</option>
          <option value="https">HTTPS</option>
          <option value="kcp">KCP</option>
          <option value="quic">QUIC</option>
        </select>
        <label>{t('dlgHost')}</label>
        <input value={host} onChange={e => setHost(e.target.value)} placeholder={t('dlgHostPlaceholder')} />
        <label>{t('dlgBindHost')}</label>
        <input value={bind} onChange={e => setBind(e.target.value)} placeholder="0.0.0.0" />
        <label>{t('dlgBindPort')}</label>
        <input
          value={port}
          onChange={e => setPort(e.target.value)}
          type="number"
          placeholder={PROTOCOL_DEFAULT_PORTS[protocol] ?? '4444'}
        />
        <label className="dialog-check">
          <input
            type="checkbox"
            checked={isHTTPS || useTLS}
            disabled={isHTTPS}
            onChange={e => setUseTLS(e.target.checked)}
          />
          <span>{isHTTPS ? t('dlgTLSHTTPS') : t('dlgTLS')}</span>
        </label>
        <label>{t('dlgPSK')}</label>
        <input
          value={psk}
          onChange={e => setPSK(e.target.value)}
          placeholder={t('dlgPSKPlaceholder')}
          type="password"
        />
        <label>{t('listenerProfile')}</label>
        <div className="dialog-row">
          <input
            value={profilePath}
            onChange={e => { setProfilePath(e.target.value); setProfile('') }}
            placeholder={t('listenerProfilePlaceholder')}
            readOnly
          />
          <button className="toolbar-btn" onClick={pickProfile}>{t('listenerProfilePick')}</button>
        </div>
        {profilePath && (
          <div className="payload-hint" style={{ marginTop: -6 }}>{t('listenerProfileLoaded')}</div>
        )}
        <div className="dialog-actions">
          <button onClick={onClose}>{t('fsCancel')}</button>
          <button className="btn-primary" onClick={handleCreate}>{t('dlgCreate')}</button>
        </div>
      </div>
    </div>
  )
}
