import { resolve } from 'node:path'
import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'
import { contentSecurityPolicy } from './src/shared/csp'

/**
 * Writes the CSP into the meta tag at build time.
 *
 * The meta tag is the policy that actually governs production: the renderer is
 * loaded with `loadFile`, and `webRequest.onHeadersReceived` — where the main
 * process installs its copy — does not fire for `file://`. Hardcoding a
 * development policy in the HTML therefore shipped `unsafe-eval` and a bare
 * `wss:` to users. Templating it from the shared source removes the chance of
 * the two drifting again.
 */
function cspPlugin(): { name: string; transformIndexHtml: (html: string) => string } {
  return {
    name: 'consoleward-csp',
    transformIndexHtml(html: string): string {
      const policy = contentSecurityPolicy(process.env['NODE_ENV'] !== 'production')
      const replaced = html.replace(
        /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")[^"]*(")/,
        `$1${policy}$2`
      )
      if (replaced === html) {
        throw new Error(
          'CSP meta tag not found in index.html — the policy would not have been applied. ' +
            'Restore the <meta http-equiv="Content-Security-Policy" content="..."> tag.'
        )
      }
      return replaced
    }
  }
}

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin()],
    resolve: {
      alias: { '@shared': resolve(__dirname, 'src/shared') }
    },
    build: {
      rollupOptions: {
        input: { index: resolve(__dirname, 'src/main/index.ts') }
      }
    }
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
    resolve: {
      alias: { '@shared': resolve(__dirname, 'src/shared') }
    },
    build: {
      rollupOptions: {
        input: { index: resolve(__dirname, 'src/preload/index.ts') }
      }
    }
  },
  renderer: {
    root: resolve(__dirname, 'src/renderer'),
    plugins: [react(), cspPlugin()],
    resolve: {
      alias: { '@shared': resolve(__dirname, 'src/shared') }
    },
    build: {
      rollupOptions: {
        input: { index: resolve(__dirname, 'src/renderer/index.html') }
      }
    }
  }
})
