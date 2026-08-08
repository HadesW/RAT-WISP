import { create } from 'zustand'

async function getEvents() {
  try {
    const mod = await import('@wailsio/runtime')
    return mod.Events
  } catch {
    return null
  }
}

export interface ListenerInfo {
  id: string
  name: string
  protocol: string
  host: string
  bind_host: string
  bind_port: number
  use_tls: boolean
  status: string
}

interface ListenerState {
  listeners: ListenerInfo[]
  setListeners: (listeners: ListenerInfo[]) => void
  updateStatus: (id: string, status: string) => void
  initEventListeners: () => void
}

export const useListenerStore = create<ListenerState>((set) => ({
  listeners: [],

  setListeners: (listeners) => set({ listeners }),

  updateStatus: (id, status) => set((state) => ({
    listeners: state.listeners.map(l =>
      l.id === id ? { ...l, status } : l
    ),
  })),

  initEventListeners: () => {
    getEvents().then(Events => {
      if (!Events) return
      Events.On('listener:status', (event: { data: { id: string; status: string } | Array<{ id: string; status: string }> }) => {
        // Wails delivers single-arg Emit payloads directly as event.data
        const data = Array.isArray(event.data) ? event.data[0] : event.data
        if (!data) return
        set((state) => ({
          listeners: state.listeners.map(l =>
            l.id === data.id ? { ...l, status: data.status } : l
          ),
        }))
      })
    })
  },
}))
