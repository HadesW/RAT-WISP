import { useState } from 'react'
import { callByName } from '../wails'
import { useListenerStore } from '../stores/useListenerStore'
import { useT } from '../i18n'

export function PayloadDialog({ onClose }: { onClose: () => void }) {
  const t = useT()
  const listeners = useListenerStore(s => s.listeners)
  const [lid, setLid] = useState(listeners[0]?.id || '')
  const [type, setType] = useState('exe')
  const [method, setMethod] = useState('template')
  const [os, setOs] = useState('windows')
  const [arch, setArch] = useState('amd64')
  const [sleep, setSleep] = useState('5000')
  const [jitter, setJitter] = useState('20')
  const [building, setBuilding] = useState(false)
  const [result, setResult] = useState('')

  // DLL (stage module) is Windows-only; switching OS resets the type to exe.
  const handleOsChange = (next: string) => {
    setOs(next)
    if (next !== 'windows') setType('exe')
  }

  const effectiveMethod = method

  const generate = async () => {
    setBuilding(true)
    setResult('')
    try {
      const path = await callByName('github.com/user/wisp/services.PayloadService.Generate', {
        listener_id: lid,
        target_os: os,
        target_arch: arch,
        type,
        method: effectiveMethod,
        sleep: parseInt(sleep),
        jitter: parseInt(jitter),
        output_path: '',
      })
      setResult(path ? `${t('payloadSuccess')}: ${path}` : `${t('payloadError')}: null`)
    } catch (e) {
      setResult(`Error: ${e}`)
    }
    setBuilding(false)
  }

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog" onClick={e => e.stopPropagation()} style={{ minWidth: 420 }}>
        <h2>{t('payloadTitle')}</h2>
        <label>{t('payloadListener')}</label>
        <select value={lid} onChange={e => setLid(e.target.value)}>
          {listeners.length === 0 && <option value="">{t('payloadNoListeners')}</option>}
          {listeners.map(l => <option key={l.id} value={l.id}>{l.name} ({l.host || l.bind_host}:{l.bind_port})</option>)}
        </select>
        <label>{t('payloadTargetOS')}</label>
        <select value={os} onChange={e => handleOsChange(e.target.value)}>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="darwin">macOS</option>
        </select>
        <label>{t('payloadType')}</label>
        <select
          value={type}
          onChange={e => setType(e.target.value)}
          disabled={os !== 'windows'}
          title={os !== 'windows' ? t('payloadTypeHint') : undefined}
        >
          <option value="exe">{t('payloadTypeExe')}</option>
          {os === 'windows' && <option value="dll">{t('payloadTypeDll')}</option>}
        </select>
        <label>{t('payloadMethod')}</label>
        <select value={method} onChange={e => setMethod(e.target.value)}>
          <option value="template">{t('payloadMethodTemplate')}</option>
          <option value="source">{t('payloadMethodSource')}</option>
        </select>
        {type === 'dll' && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
            {t('payloadDllSourceHint')}
          </div>
        )}
        <label>{t('payloadArch')}</label>
        <select value={arch} onChange={e => setArch(e.target.value)}>
          <option value="amd64">x64</option>
          <option value="arm64">ARM64</option>
        </select>
        <label>{t('payloadSleep')}</label>
        <input value={sleep} onChange={e => setSleep(e.target.value)} type="number" min={10} step={100} placeholder="5000" />
        <label>{t('payloadJitter')}</label>
        <input value={jitter} onChange={e => setJitter(e.target.value)} type="number" min={0} max={100} placeholder="0-100" />
        {result && (
          <div style={{
            padding: 8,
            borderRadius: 6,
            background: result.startsWith('Error') ? 'rgba(229,72,77,0.12)' : 'rgba(46,160,67,0.12)',
            color: result.startsWith('Error') ? '#e5484d' : '#2ea043',
            fontSize: 12,
            marginTop: 8,
            wordBreak: 'break-all',
          }}>
            {result}
          </div>
        )}
        <div className="dialog-actions">
          <button onClick={onClose}>{t('fsCancel')}</button>
          <button className="btn-primary" onClick={generate} disabled={building || !lid}>
            {building ? t('payloadGenerating') : t('payloadGenerate')}
          </button>
        </div>
      </div>
    </div>
  )
}
