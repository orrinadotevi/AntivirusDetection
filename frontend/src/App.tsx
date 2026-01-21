import React, { useMemo, useState } from 'react'

type ScanResponse = {
  filename: string
  label: 'safe' | 'malware'
  malware_probability: number | null
  features: Record<string, number>
}

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

function classNames(...classes: Array<string | false | undefined | null>) {
  return classes.filter(Boolean).join(' ')
}

export default function App() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<ScanResponse | null>(null)
  const [featureQuery, setFeatureQuery] = useState('')

  const filteredFeatures = useMemo(() => {
    if (!result) return []
    const entries = Object.entries(result.features)
    const q = featureQuery.trim().toLowerCase()
    if (!q) return entries
    return entries.filter(([k]) => k.toLowerCase().includes(q))
  }, [result, featureQuery])

  async function runScan() {
    if (!file) return
    setLoading(true)
    setError(null)
    setResult(null)

    const form = new FormData()
    form.append('file', file)

    try {
      const resp = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        body: form,
      })

      const data = await resp.json()
      if (!resp.ok) {
        throw new Error(data?.detail || 'Scan failed')
      }
      setResult(data)
    } catch (e: any) {
      setError(e?.message || 'Unexpected error')
    } finally {
      setLoading(false)
    }
  }

  function onPickFile(f: File | null) {
    setFile(f)
    setError(null)
    setResult(null)
  }

  function onDrop(e: React.DragEvent) {
    e.preventDefault()
    const f = e.dataTransfer.files?.[0]
    if (f) onPickFile(f)
  }

  const score = result?.malware_probability ?? null
  const percent = score == null ? null : Math.round(score * 100)

  return (
    <div className="min-h-screen">
      <header className="mx-auto max-w-6xl px-6 pt-10">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">AntivirusDetection</h1>
            <p className="mt-1 text-sm text-slate-300">
              Upload a Windows PE file to classify it with a bundled ML model.
            </p>
          </div>
          <a
            className="text-sm text-slate-300 hover:text-white"
            href="https://github.com"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-6 pb-16 pt-8">
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Upload Card */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 shadow-xl shadow-black/20">
            <h2 className="text-lg font-medium">Scan a file</h2>
            <p className="mt-1 text-sm text-slate-300">
              Drag & drop a file, or choose one from your computer.
            </p>

            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={onDrop}
              className={classNames(
                'mt-4 rounded-xl border border-dashed p-6 transition',
                'border-slate-700 bg-slate-950/30 hover:bg-slate-950/50'
              )}
            >
              <div className="flex flex-col items-center justify-center text-center">
                <div className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300">
                  .exe · .dll · .sys
                </div>

                <div className="mt-4">
                  <input
                    type="file"
                    className="hidden"
                    id="file"
                    onChange={(e) => onPickFile(e.target.files?.[0] || null)}
                  />
                  <label
                    htmlFor="file"
                    className="cursor-pointer rounded-lg bg-white/10 px-4 py-2 text-sm font-medium hover:bg-white/15"
                  >
                    Choose file
                  </label>
                </div>

                {file ? (
                  <div className="mt-4 text-sm">
                    <div className="font-medium text-slate-100">{file.name}</div>
                    <div className="text-slate-400">{Math.round(file.size / 1024).toLocaleString()} KB</div>
                  </div>
                ) : (
                  <div className="mt-4 text-sm text-slate-400">No file selected</div>
                )}
              </div>
            </div>

            <div className="mt-4 flex items-center gap-3">
              <button
                onClick={runScan}
                disabled={!file || loading}
                className={classNames(
                  'rounded-lg px-4 py-2 text-sm font-semibold transition',
                  !file || loading
                    ? 'cursor-not-allowed bg-slate-800 text-slate-500'
                    : 'bg-indigo-500/90 text-white hover:bg-indigo-500'
                )}
              >
                {loading ? 'Scanning…' : 'Run scan'}
              </button>
              <div className="text-xs text-slate-400">
                Backend: <span className="font-mono">{API_BASE}</span>
              </div>
            </div>

            {error ? (
              <div className="mt-4 rounded-xl border border-rose-900/50 bg-rose-950/40 p-4 text-sm text-rose-200">
                {error}
              </div>
            ) : null}

            <div className="mt-6 text-xs text-slate-500">
              For learning use only. Results can be wrong—don’t rely on this to make security decisions.
            </div>
          </div>

          {/* Results Card */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/50 p-6 shadow-xl shadow-black/20">
            <h2 className="text-lg font-medium">Results</h2>
            <p className="mt-1 text-sm text-slate-300">Classification + feature breakdown.</p>

            {!result ? (
              <div className="mt-6 rounded-xl border border-slate-800 bg-slate-950/30 p-6 text-sm text-slate-400">
                Upload a file and run a scan to see results.
              </div>
            ) : (
              <div className="mt-6 space-y-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm text-slate-400">File</div>
                    <div className="mt-1 break-all font-medium text-slate-100">{result.filename}</div>
                  </div>
                  <div
                    className={classNames(
                      'rounded-full px-3 py-1 text-xs font-semibold',
                      result.label === 'malware'
                        ? 'bg-rose-500/15 text-rose-200 ring-1 ring-rose-500/40'
                        : 'bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/40'
                    )}
                  >
                    {result.label.toUpperCase()}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-950/30 p-4">
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium">Malware score</div>
                    <div className="text-sm text-slate-300">
                      {percent == null ? 'N/A' : `${percent}%`}
                    </div>
                  </div>
                  <div className="mt-3 h-2 rounded-full bg-slate-800">
                    <div
                      className={classNames(
                        'h-2 rounded-full transition-all',
                        result.label === 'malware' ? 'bg-rose-400' : 'bg-emerald-400'
                      )}
                      style={{ width: `${percent ?? 0}%` }}
                    />
                  </div>
                  <div className="mt-2 text-xs text-slate-500">
                    This is the model’s probability for class=1 (malware), when available.
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-sm font-medium">Features</div>
                    <input
                      value={featureQuery}
                      onChange={(e) => setFeatureQuery(e.target.value)}
                      placeholder="Filter…"
                      className="w-40 rounded-lg border border-slate-700 bg-slate-950/40 px-3 py-1.5 text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/60"
                    />
                  </div>

                  <div className="mt-3 max-h-[320px] overflow-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs">
                      <thead className="sticky top-0 bg-slate-900/90 text-slate-300 backdrop-blur">
                        <tr>
                          <th className="px-3 py-2 font-semibold">Name</th>
                          <th className="px-3 py-2 font-semibold">Value</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredFeatures.map(([k, v]) => (
                          <tr key={k} className="border-t border-slate-800">
                            <td className="px-3 py-2 font-mono text-slate-200">{k}</td>
                            <td className="px-3 py-2 text-slate-300">{Number(v).toFixed(4)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        <footer className="mt-10 text-center text-xs text-slate-500">
          Built with FastAPI + React. Educational demo.
        </footer>
      </main>
    </div>
  )
}
