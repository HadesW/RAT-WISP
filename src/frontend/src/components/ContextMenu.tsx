import { useEffect, useLayoutEffect, useRef, useState } from 'react'

export interface ContextMenuItem {
  label?: string
  onClick?: () => void
  danger?: boolean
  disabled?: boolean
  separator?: boolean
  submenu?: ContextMenuItem[]
  keepOpen?: boolean // keep the menu open after the click (e.g. column toggles)
}

interface ContextMenuProps {
  x: number
  y: number
  items: ContextMenuItem[]
  onClose: () => void
}

export function ContextMenu({ x, y, items, onClose }: ContextMenuProps) {
  const ref = useRef<HTMLDivElement>(null)
  const nestedRef = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState({ x, y })
  const [openSub, setOpenSub] = useState<number | null>(null)

  // Close on Esc and on outside click
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    const onMouseDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    window.addEventListener('keydown', onKey)
    window.addEventListener('mousedown', onMouseDown)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('mousedown', onMouseDown)
    }
  }, [onClose])

  // Flip the menu near the window edges
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    const rect = el.getBoundingClientRect()
    let nx = x
    let ny = y
    if (x + rect.width > window.innerWidth - 8) nx = Math.max(8, window.innerWidth - rect.width - 8)
    if (y + rect.height > window.innerHeight - 8) ny = Math.max(8, window.innerHeight - rect.height - 8)
    setPos({ x: nx, y: ny })
  }, [x, y])

  // Flip the open submenu near the right / bottom window edges
  useLayoutEffect(() => {
    const el = nestedRef.current
    if (!el) return
    const r = el.getBoundingClientRect()
    if (r.right > window.innerWidth - 8) {
      el.style.left = 'auto'
      el.style.right = '100%'
    } else {
      el.style.left = '100%'
      el.style.right = 'auto'
    }
    if (r.bottom > window.innerHeight - 8) {
      el.style.top = `${Math.max(-r.height + 8, window.innerHeight - 8 - r.bottom)}px`
    }
  }, [openSub])

  const renderItem = (item: ContextMenuItem, i: number) => {
    if (item.separator) return <div key={i} className="context-menu-sep" />
    if (item.submenu && item.submenu.length > 0) {
      return (
        <div
          key={i}
          className="context-menu-sub"
          onMouseEnter={() => setOpenSub(i)}
          onClick={() => setOpenSub(openSub === i ? null : i)}
        >
          <button className="context-menu-item" tabIndex={-1}>
            {item.label}
            <span className="context-menu-arrow">›</span>
          </button>
          {openSub === i && (
            <div ref={nestedRef} className="context-menu nested">
              {item.submenu.map((child, j) =>
                child.separator ? (
                  <div key={j} className="context-menu-sep" />
                ) : (
                  <button
                    key={j}
                    className={`context-menu-item${child.danger ? ' danger' : ''}`}
                    disabled={child.disabled}
                    onClick={() => {
                      if (!child.keepOpen) onClose()
                      child.onClick?.()
                    }}
                  >
                    {child.label}
                  </button>
                ),
              )}
            </div>
          )}
        </div>
      )
    }
    return (
      <button
        key={i}
        className={`context-menu-item${item.danger ? ' danger' : ''}`}
        disabled={item.disabled}
        onClick={() => {
          if (!item.keepOpen) onClose()
          item.onClick?.()
        }}
      >
        {item.label}
      </button>
    )
  }

  return (
    <div
      ref={ref}
      className="context-menu"
      style={{ left: pos.x, top: pos.y }}
      onContextMenu={e => e.preventDefault()}
    >
      {items.map(renderItem)}
    </div>
  )
}
