import { useState } from 'react'
import { PayloadDialog } from './PayloadDialog'

export function Toolbar() {
  const [showPayload, setShowPayload] = useState(false)

  return (
    <>
      <div className="toolbar">
        <button className="toolbar-btn" onClick={() => setShowPayload(true)}>
          Generate Payload
        </button>
        <div className="toolbar-sep" />
        <button className="toolbar-btn">
          Listeners
        </button>
        <div className="spacer" />
        <span style={{ fontSize: 11, color: 'var(--text-dim)' }}>
          Wisp v1.0.0
        </span>
      </div>
      {showPayload && <PayloadDialog onClose={() => setShowPayload(false)} />}
    </>
  )
}
