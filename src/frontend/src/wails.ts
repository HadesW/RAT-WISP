// Wails runtime wrapper
// Uses the built-in /wails/runtime.js served by Wails in the WebView

let runtimeModule: any = null
let runtimeLoading: Promise<any> | null = null

async function getRuntime(): Promise<any> {
  if (runtimeModule) return runtimeModule
  if (!runtimeLoading) {
    runtimeLoading = import('wails-runtime').catch(() => null)
  }
  runtimeModule = await runtimeLoading
  return runtimeModule
}

export async function callByName(methodName: string, ...args: unknown[]): Promise<any> {
  const runtime = await getRuntime()
  if (!runtime?.Call?.ByName) {
    throw new Error('Wails runtime not available')
  }
  return runtime.Call.ByName(methodName, ...args)
}

export async function onEvent(name: string, callback: (data: any) => void) {
  const runtime = await getRuntime()
  if (runtime?.Events?.On) {
    runtime.Events.On(name, (event: any) => {
      // Wails delivers a single-arg Emit payload directly as event.data (not an
      // array). Only index into it when it really is an array — string payloads
      // must stay intact.
      const data = Array.isArray(event?.data) ? event.data[0] : event?.data ?? event
      callback(data)
    })
  }
}
