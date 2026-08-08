declare module 'wails-runtime' {
  export const Call: {
    ByName(methodName: string, ...args: any[]): Promise<any>
    ByID(methodID: number, ...args: any[]): Promise<any>
  }
  export const Events: {
    On(eventName: string, callback: (event: any) => void): () => void
    Emit(eventName: string, data?: any): void
  }
}

