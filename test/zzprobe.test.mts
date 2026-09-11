// temporary probe — delete after
import { describe, test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { createServer, request } from 'node:http'
import type { AddressInfo } from 'node:net'

const SERVER_TOKEN = 'PZ2s7Wd0m3n5FQ0RkGm4tYbXH1qLcJ8vE6oS9rT2uA0'
const vaultState = { unlocked: true, data: { settings: { mcpPort: 0 }, mcpToken: SERVER_TOKEN } }

let gateSeen = false
let immediateFired = false
let immediateFiredAtBridge: boolean | null = null
let gateCalls = 0

mock.module('electron', { exports: { app: { getPath: () => '' } } })
mock.module('../src/main/vault.ts', {
  exports: {
    vault: {
      isUnlocked: (): boolean => {
        gateCalls++
        if (!gateSeen) {
          gateSeen = true
          setImmediate(() => { immediateFired = true })
        }
        return vaultState.unlocked
      },
      read: () => vaultState.data,
      mutate: async (): Promise<void> => {}
    }
  }
})
mock.module('../src/main/ssh.ts', {
  exports: {
    UPLOAD_MAX_BYTES: 1024 * 1024,
    ssh: { isReady: () => true, title: () => 'web01', listForModel: () => [], readText: () => 'p',
           remoteHome: async (): Promise<string> => '/home/deploy', upload: async (): Promise<void> => {} }
  }
})
mock.module('../src/main/aiLog.ts', { exports: { aiLog: { record: async (): Promise<void> => {} } } })

const { mcp } = await import('../src/main/mcp.ts')

// `buildServer()` is the statement immediately after `await readJsonBody(req)`,
// so it marks the instant the body wait ends.
const anyMcp = mcp as unknown as { buildServer: () => unknown }
const realBuild = anyMcp.buildServer.bind(mcp)
let afterBodyImmediate = false
anyMcp.buildServer = (): unknown => {
  afterBodyImmediate = false
  setImmediate(() => { afterBodyImmediate = true })
  return realBuild()
}

async function freePort(): Promise<number> {
  const probe = createServer()
  await new Promise<void>((r) => probe.listen(0, '127.0.0.1', r))
  const { port } = probe.address() as AddressInfo
  await new Promise<void>((r) => probe.close(() => r()))
  return port
}

describe('probe', () => {
  test('turns between the http vault gate and the bridge call', async () => {
    const port = await freePort()
    vaultState.data.settings.mcpPort = port
    await mcp.start()
    mcp.bind({
      askCommand: async () => ({ approved: false, autoShare: false }),
      askShare: async () => ({ shared: false, text: '' }),
      askUpload: async () => ({ approved: false }),
      saveCommand: async () => {
        immediateFiredAtBridge = afterBodyImmediate
        return { approved: false }
      }
    })

    const body = JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'save_command', arguments: { title: 'x', body: 'ls', reason: 'why' } }
    })

    await new Promise<void>((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port, method: 'POST', agent: false,
        headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
                   authorization: `Bearer ${SERVER_TOKEN}`, 'content-length': Buffer.byteLength(body) } },
        (res) => { res.resume(); res.on('end', () => resolve()) })
      req.on('error', reject)
      req.end(body)
    })

    console.log('PROBE gateCalls=', gateCalls, 'turnElapsedAfterBodyBeforeBridge=', immediateFiredAtBridge)
    await mcp.stop()
    assert.equal(immediateFiredAtBridge, false, 'an event-loop turn elapsed between readJsonBody resolving and the bridge call')
  })
})
