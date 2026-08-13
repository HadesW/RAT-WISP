import { useState } from 'react'
import { callByName } from '../wails'
import { useListenerStore } from '../stores/useListenerStore'
import { useT } from '../i18n'

type Mode = 'agent' | 'shellcode' | 'staged' | 'delivery'

// Groups make the payload dialog navigable: the fields are large enough that
// a flat list is unwieldy. Each group is a bordered card with a header.
const MODES: { id: Mode; labelKey: string }[] = [
  { id: 'agent', labelKey: 'payloadModeAgent' },
  { id: 'shellcode', labelKey: 'payloadModeShellcode' },
  { id: 'staged', labelKey: 'payloadModeStaged' },
  { id: 'delivery', labelKey: 'payloadModeDelivery' },
]

function Group({ title, children, defaultOpen = true }: {
  title: string
  children: React.ReactNode
  defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <fieldset className="payload-group">
      <legend className="payload-group-title" onClick={() => setOpen(!open)}>
        <span className={`payload-caret${open ? ' open' : ''}`}>▾</span>
        {title}
      </legend>
      {open && <div className="payload-group-body">{children}</div>}
    </fieldset>
  )
}

function Row({ children }: { children: React.ReactNode }) {
  return <div className="payload-row">{children}</div>
}

function Field({ label, children, hint }: {
  label: string
  children: React.ReactNode
  hint?: string
}) {
  return (
    <div className="payload-field">
      <label>{label}</label>
      {children}
      {hint && <div className="payload-hint">{hint}</div>}
    </div>
  )
}

export function PayloadDialog({ onClose }: { onClose: () => void }) {
  const t = useT()
  const listeners = useListenerStore(s => s.listeners)
  const [lid, setLid] = useState(listeners[0]?.id || '')
  const [mode, setMode] = useState<Mode>('agent')
  const [type, setType] = useState('exe')
  const [method, setMethod] = useState('template')
  const [format, setFormat] = useState('raw')
  const [deliveryFormat, setDeliveryFormat] = useState('hta')
  const [poly, setPoly] = useState(false)
  const [stagerLang, setStagerLang] = useState('go')
  const [stageTTL, setStageTTL] = useState('0')
  const [reuseStage, setReuseStage] = useState(false)
  const [os, setOs] = useState('windows')
  const [arch, setArch] = useState('amd64')
  const [sleep, setSleep] = useState('5000')
  const [jitter, setJitter] = useState('20')
  const [trafficUA, setTrafficUA] = useState('')
  const [trafficURI, setTrafficURI] = useState('')
  const [building, setBuilding] = useState(false)
  const [result, setResult] = useState('')
  const [showTraffic, setShowTraffic] = useState(false)

  const trafficProfile = () => {
    const lines = (s: string) => s.split('\n').map(x => x.trim()).filter(Boolean)
    const uas = lines(trafficUA)
    const uris = lines(trafficURI)
    if (uas.length === 0 && uris.length === 0) return undefined
    return { user_agents: uas, uris }
  }

  const handleOsChange = (next: string) => {
    setOs(next)
    if (next !== 'windows') setType('exe')
  }

  const restricted = mode !== 'agent'
  const handleModeChange = (m: Mode) => {
    setMode(m)
    if (m !== 'agent') {
      setOs('windows')
      setArch('amd64')
    }
  }

  const generate = async () => {
    setBuilding(true)
    setResult('')
    try {
      let out: any
      if (mode === 'shellcode') {
        out = await callByName('github.com/user/wisp/services.ShellcodeService.GenerateShellcode', {
          listener_id: lid, target_os: os, target_arch: arch, mode: 'shellcode',
          format, poly, traffic_profile: trafficProfile(),
          sleep: parseInt(sleep), jitter: parseInt(jitter), output_path: '',
        })
        setResult(out ? `${t('payloadSuccess')}: ${out}` : `${t('payloadError')}: null`)
      } else if (mode === 'delivery') {
        out = await callByName('github.com/user/wisp/services.ShellcodeService.GenerateDelivery', {
          listener_id: lid, target_os: os, target_arch: arch, format: deliveryFormat,
          poly, traffic_profile: trafficProfile(),
          sleep: parseInt(sleep), jitter: parseInt(jitter), output_path: '',
        })
        setResult(out ? `${t('payloadSuccess')}: ${out}` : `${t('payloadError')}: null`)
      } else if (mode === 'staged') {
        out = await callByName('github.com/user/wisp/services.ShellcodeService.GenerateStager', {
          listener_id: lid, target_os: os, target_arch: arch, mode: 'staged',
          stager_lang: stagerLang, format, stage_ttl_minutes: parseInt(stageTTL) || 0,
          reuse_stage: reuseStage, traffic_profile: trafficProfile(),
          sleep: parseInt(sleep), jitter: parseInt(jitter), output_path: '',
        })
        if (out?.stager_path) {
          const extra = out.stage_url ? `\n${t('payloadStageInfo')}\n${out.stage_url}` : ''
          setResult(`${t('payloadSuccess')}: ${out.stager_path}${extra}`)
        } else {
          setResult(`${t('payloadError')}: null`)
        }
      } else {
        const path = await callByName('github.com/user/wisp/services.PayloadService.Generate', {
          listener_id: lid, target_os: os, target_arch: arch, type, method,
          traffic_profile: trafficProfile(),
          sleep: parseInt(sleep), jitter: parseInt(jitter), output_path: '',
        })
        setResult(path ? `${t('payloadSuccess')}: ${path}` : `${t('payloadError')}: null`)
      }
    } catch (e) {
      setResult(`Error: ${e}`)
    }
    setBuilding(false)
  }

  return (
    <div className="dialog-overlay" onClick={onClose}>
      <div className="dialog payload-dialog" onClick={e => e.stopPropagation()}>
        <div className="payload-header">
          <div>
            <h2>{t('payloadTitle')}</h2>
            <div className="payload-sub">{t('payloadModeHint')}</div>
          </div>
          <button className="payload-close" onClick={onClose} aria-label="close">×</button>
        </div>

        {/* Step 1 — mode */}
        <div className="payload-mode-tabs">
          {MODES.map(m => (
            <button
              key={m.id}
              className={`payload-mode-tab${mode === m.id ? ' active' : ''}`}
              onClick={() => handleModeChange(m.id)}
            >
              {t(m.labelKey)}
            </button>
          ))}
        </div>

        {/* Step 2 — target */}
        <Group title={t('payloadTarget')}>
          <Row>
            <Field label={t('payloadListener')}>
              <select value={lid} onChange={e => setLid(e.target.value)}>
                {listeners.length === 0 && <option value="">{t('payloadNoListeners')}</option>}
                {listeners.map(l => (
                  <option key={l.id} value={l.id}>{l.name} ({l.host || l.bind_host}:{l.bind_port})</option>
                ))}
              </select>
            </Field>
          </Row>
          <Row>
            <Field label={t('payloadTargetOS')}>
              <select value={os} onChange={e => handleOsChange(e.target.value)} disabled={restricted}>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="darwin">macOS</option>
              </select>
            </Field>
            <Field label={t('payloadArch')}>
              <select value={arch} onChange={e => setArch(e.target.value)} disabled={restricted}>
                <option value="amd64">x64</option>
                <option value="arm64">ARM64</option>
              </select>
            </Field>
          </Row>
        </Group>

        {/* Step 3 — payload options (mode-specific) */}
        <Group title={t('payloadOptions')}>
          {mode === 'shellcode' && (
            <Row>
              <Field label={t('payloadFormat')}>
                <select value={format} onChange={e => setFormat(e.target.value)}>
                  <option value="raw">{t('payloadFormatRaw')}</option>
                  <option value="b64">{t('payloadFormatB64')}</option>
                  <option value="c">{t('payloadFormatC')}</option>
                  <option value="csharp">{t('payloadFormatCSharp')}</option>
                  <option value="powershell">{t('payloadFormatPowerShell')}</option>
                  <option value="python">{t('payloadFormatPython')}</option>
                  <option value="vba">{t('payloadFormatVBA')}</option>
                  <option value="hta">{t('payloadFormatHTA')}</option>
                </select>
              </Field>
              <label className="payload-check" style={{ alignSelf: 'flex-end', marginBottom: 4 }}>
                <input type="checkbox" checked={poly} onChange={e => setPoly(e.target.checked)} />
                <span>{t('payloadPoly')}</span>
              </label>
            </Row>
          )}

          {mode === 'delivery' && (
            <Row>
              <Field label={t('payloadDelivery')} hint={t('payloadDeliveryInfo')}>
                <select value={deliveryFormat} onChange={e => setDeliveryFormat(e.target.value)}>
                  <option value="lnk">{t('payloadDeliveryLNK')}</option>
                  <option value="hta">{t('payloadDeliveryHTA')}</option>
                  <option value="html">{t('payloadDeliveryHTML')}</option>
                  <option value="ps1">{t('payloadDeliveryPS1')}</option>
                </select>
              </Field>
              <label className="payload-check" style={{ alignSelf: 'flex-end', marginBottom: 4 }}>
                <input type="checkbox" checked={poly} onChange={e => setPoly(e.target.checked)} />
                <span>{t('payloadPoly')}</span>
              </label>
            </Row>
          )}

          {mode === 'staged' && (
            <>
              <Row>
                <Field label={t('payloadStagerLang')} hint={stagerLang === 'c' ? t('payloadStagerLangCHint') : undefined}>
                  <select value={stagerLang} onChange={e => setStagerLang(e.target.value)}>
                    <option value="go">{t('payloadStagerLangGo')}</option>
                    <option value="c">{t('payloadStagerLangC')}</option>
                  </select>
                </Field>
                {stagerLang === 'c' && (
                  <Field label={t('payloadFormat')}>
                    <select value={format} onChange={e => setFormat(e.target.value)}>
                      <option value="exe">{t('payloadFormatExe')}</option>
                      <option value="dll">{t('payloadFormatDll')}</option>
                      <option value="raw">{t('payloadFormatRaw')}</option>
                      <option value="b64">{t('payloadFormatB64')}</option>
                      <option value="c">{t('payloadFormatC')}</option>
                      <option value="csharp">{t('payloadFormatCSharp')}</option>
                      <option value="powershell">{t('payloadFormatPowerShell')}</option>
                      <option value="python">{t('payloadFormatPython')}</option>
                      <option value="vba">{t('payloadFormatVBA')}</option>
                      <option value="hta">{t('payloadFormatHTA')}</option>
                    </select>
                  </Field>
                )}
              </Row>
              <Row>
                <Field label={t('payloadStageTTL')} hint={t('payloadStageTTLHint')}>
                  <input value={stageTTL} onChange={e => setStageTTL(e.target.value)} type="number" min={0} placeholder="0" />
                </Field>
                <label className="payload-check" style={{ alignSelf: 'flex-end', marginBottom: 4 }}>
                  <input type="checkbox" checked={reuseStage} onChange={e => setReuseStage(e.target.checked)} />
                  <span>{t('payloadReuseStage')}</span>
                </label>
              </Row>
            </>
          )}

          {mode === 'agent' && (
            <>
              <Row>
                <Field label={t('payloadType')} hint={os !== 'windows' ? t('payloadTypeHint') : undefined}>
                  <select
                    value={type}
                    onChange={e => setType(e.target.value)}
                    disabled={os !== 'windows'}
                    title={os !== 'windows' ? t('payloadTypeHint') : undefined}
                  >
                    <option value="exe">{t('payloadTypeExe')}</option>
                    {os === 'windows' && <option value="dll">{t('payloadTypeDll')}</option>}
                  </select>
                </Field>
                <Field label={t('payloadMethod')}>
                  <select value={method} onChange={e => setMethod(e.target.value)}>
                    <option value="template">{t('payloadMethodTemplate')}</option>
                    <option value="source">{t('payloadMethodSource')}</option>
                  </select>
                </Field>
              </Row>
              {type === 'dll' && (
                <div className="payload-hint">{t('payloadDllSourceHint')}</div>
              )}
            </>
          )}

          <Row>
            <Field label={t('payloadSleep')}>
              <input value={sleep} onChange={e => setSleep(e.target.value)} type="number" min={10} step={100} placeholder="5000" />
            </Field>
            <Field label={t('payloadJitter')}>
              <input value={jitter} onChange={e => setJitter(e.target.value)} type="number" min={0} max={100} placeholder="0-100" />
            </Field>
          </Row>
        </Group>

        {/* Step 4 — traffic profile (collapsible) */}
        <fieldset className="payload-group">
          <legend className="payload-group-title" onClick={() => setShowTraffic(!showTraffic)}>
            <span className={`payload-caret${showTraffic ? ' open' : ''}`}>▾</span>
            {t('payloadTrafficProfile')}
          </legend>
          {showTraffic && (
            <div className="payload-group-body">
              <Field label={t('payloadTrafficUA')}>
                <textarea
                  value={trafficUA}
                  onChange={e => setTrafficUA(e.target.value)}
                  rows={2}
                  placeholder={'Mozilla/5.0 (Windows NT 10.0; Win64; x64)\nMozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'}
                />
              </Field>
              <Field label={t('payloadTrafficURI')}>
                <textarea
                  value={trafficURI}
                  onChange={e => setTrafficURI(e.target.value)}
                  rows={2}
                  placeholder={'/api/v1/checkin\n/wp-login.php\n/ping'}
                />
              </Field>
              <div className="payload-hint">{t('payloadTrafficHint')}</div>
            </div>
          )}
        </fieldset>

        {/* Result + actions */}
        {result && (
          <div className={`payload-result${result.startsWith('Error') ? ' err' : ' ok'}`}>
            {result}
          </div>
        )}
        <div className="dialog-actions payload-actions">
          <button onClick={onClose}>{t('fsCancel')}</button>
          <button className="btn-primary" onClick={generate} disabled={building || !lid}>
            {building ? t('payloadGenerating') : t('payloadGenerate')}
          </button>
        </div>
      </div>
    </div>
  )
}
