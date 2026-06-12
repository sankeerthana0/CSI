import React, { useState } from 'react';
import { Play, Copy, Check, Terminal, Code, Cpu } from 'lucide-react';

interface FastApiSandboxProps {
  onRunQuery: (query: string) => Promise<any>;
  onIngestLog: (log: { title: string; content: string; source: string; severity: string; techniques: string[]; ips: string[] }) => Promise<any>;
}

export const FastApiSandbox: React.FC<FastApiSandboxProps> = ({ onRunQuery, onIngestLog }) => {
  const [activeTab, setActiveTab] = useState<'run' | 'ingest' | 'health' | 'history'>('run');
  const [queryInput, setQueryInput] = useState('{"query": "Analyze LockBit Ransomware activity from suspicious Powershell logs and recommend countermeasures", "customLogId": ""}');
  const [logInput, setLogInput] = useState(`{
  "title": "Abnormal SSH Bruteforce",
  "source": "Linux-AuthLog",
  "content": "Failed password for root from 185.120.34.12 port 3982 ssh2",
  "severity": "HIGH",
  "techniques": ["T1110.001"],
  "ips": ["185.120.34.12"]
}`);
  
  const [response, setResponse] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [stats, setStats] = useState<{ status: string; statusText: string; time: number } | null>(null);
  const [copied, setCopied] = useState(false);

  const endpoints = {
    run: {
      method: 'POST',
      path: '/api/agents/run',
      desc: 'Orchestrator endpoint triggers the multi-agent flow. Traces each node (Ingest, Retrieve, Analysis, Summarize, Alert, Evaluator) and scores context fidelity.',
      curl: `curl -X POST "${window.location.origin}/api/agents/run" \\
  -H "Content-Type: application/json" \\
  -d '${queryInput.replace(/\n\s*/g, '')}'`
    },
    ingest: {
      method: 'POST',
      path: '/api/ingest',
      desc: 'Inject new syslogs or threat indicator reports directly into the Multi-Agent input stream.',
      curl: `curl -X POST "${window.location.origin}/api/ingest" \\
  -H "Content-Type: application/json" \\
  -d '${logInput.replace(/\n\s*/g, '')}'`
    },
    health: {
      method: 'GET',
      path: '/api/health',
      desc: 'Utility status endpoint reporting orchestrator integrity, database size catalog, and Gemini model availability coordinates.',
      curl: `curl -X GET "${window.location.origin}/api/health"`
    },
    history: {
      method: 'GET',
      path: '/api/evaluation/history',
      desc: 'Retrieve historic multi-agent system runs logs, including individual agent metrics and qualitative critic scores.',
      curl: `curl -X GET "${window.location.origin}/api/evaluation/history"`
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(endpoints[activeTab].curl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const executeCall = async () => {
    setIsLoading(true);
    setResponse('');
    setStats(null);
    const start = Date.now();
    try {
      let res;
      if (activeTab === 'run') {
        const parsed = JSON.parse(queryInput);
        const requestOptions = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed)
        };
        const fetchRes = await fetch('/api/agents/run', requestOptions);
        res = await fetchRes.json();
      } else if (activeTab === 'ingest') {
        const parsed = JSON.parse(logInput);
        const requestOptions = {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed)
        };
        const fetchRes = await fetch('/api/ingest', requestOptions);
        res = await fetchRes.json();
      } else if (activeTab === 'health') {
        const fetchRes = await fetch('/api/health');
        res = await fetchRes.json();
      } else {
        const fetchRes = await fetch('/api/evaluation/history');
        res = await fetchRes.json();
      }

      setResponse(JSON.stringify(res, null, 2));
      setStats({
        status: "200 OK",
        statusText: "Success",
        time: Date.now() - start
      });
    } catch (e: any) {
      setResponse(JSON.stringify({ error: "Malformed JSON payload or connection failure", details: e.message }, null, 2));
      setStats({
        status: "500 Error",
        statusText: "Failed execution",
        time: Date.now() - start
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-6 shadow-2xl relative">
      <div className="border-b border-zinc-800 pb-4 mb-6">
        <h3 className="text-md font-mono font-semibold text-white flex items-center gap-2">
          <Terminal className="h-4.5 w-4.5 text-indigo-400" />
          FASTAPI INTERACTIVE API SANDBOX
        </h3>
        <p className="text-xs text-zinc-400 mt-1">
          Simulate SIEM or monitoring alerts, inspect Curl code payloads, and dispatch real HTTP commands.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Endpoint Navigation Sidebar */}
        <div className="lg:col-span-4 flex flex-col gap-2">
          <span className="text-[10px] font-mono font-bold text-zinc-500 tracking-wider mb-1">API ROUTE SCHEMAS</span>
          
          {(['run', 'ingest', 'health', 'history'] as const).map(tab => {
            const ep = endpoints[tab];
            const isPost = ep.method === 'POST';
            return (
              <button
                key={tab}
                onClick={() => {
                  setActiveTab(tab);
                  setResponse('');
                  setStats(null);
                }}
                className={`flex flex-col items-start p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  activeTab === tab
                    ? 'bg-zinc-900 border-indigo-500/60 ring-1 ring-indigo-500/10'
                    : 'bg-zinc-950/40 border-zinc-950 hover:bg-zinc-900/40 hover:border-zinc-800'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded ${
                    isPost ? 'bg-indigo-950/40 text-indigo-300 border border-indigo-500/15' : 'bg-emerald-950/20 text-emerald-400 border border-emerald-500/20'
                  }`}>
                    {ep.method}
                  </span>
                  <span className="text-xs font-mono font-bold text-zinc-200">{ep.path}</span>
                </div>
                <span className="text-[10px] text-zinc-400 line-clamp-2 leading-relaxed">{ep.desc}</span>
              </button>
            );
          })}
        </div>

        {/* API Details Panel & Payload Input */}
        <div className="lg:col-span-8 flex flex-col gap-4">
          <div className="bg-zinc-950 p-4 rounded-lg border border-zinc-900 flex-grow shadow-inner">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-3 mb-4">
              <span className="text-xs font-mono font-bold text-zinc-300">REQUEST SCHEMA CONFIGURATION</span>
              <button
                onClick={handleCopy}
                className="text-zinc-400 hover:text-white p-1 rounded hover:bg-zinc-900 flex items-center gap-1 text-[10px] font-mono cursor-pointer transition-all"
                title="Copy Curl Command"
              >
                {copied ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-400" />
                    <span>COPIED</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3" />
                    <span>COPY CURL</span>
                  </>
                )}
              </button>
            </div>

            {/* Curl Display block */}
            <div className="mb-4">
              <span className="text-[10px] font-mono text-zinc-500 block mb-1">CURL SHELL EXAMPLE</span>
              <pre className="bg-[#0B0B0E] p-3 rounded border border-zinc-805 font-mono text-[10px] text-indigo-400/90 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {endpoints[activeTab].curl}
              </pre>
            </div>

            {/* Editable JSON parameters */}
            {(activeTab === 'run' || activeTab === 'ingest') && (
              <div>
                <span className="text-[10px] font-mono text-zinc-500 block mb-1">EDITABLE HTTP JSON BODY</span>
                <textarea
                  rows={5}
                  value={activeTab === 'run' ? queryInput : logInput}
                  onChange={e => activeTab === 'run' ? setQueryInput(e.target.value) : setLogInput(e.target.value)}
                  className="w-full bg-[#0B0B0E] border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded p-3 font-mono text-xs text-zinc-300 leading-relaxed"
                />
              </div>
            )}

            {/* Invariant status indicators */}
            {!(activeTab === 'run' || activeTab === 'ingest') && (
              <div className="bg-[#0B0B0E] p-6 rounded border border-zinc-800 text-center py-10">
                <Cpu className="h-8 w-8 text-zinc-650 mx-auto mb-2 animate-pulse" />
                <h5 className="text-xs font-mono text-zinc-400">Zero-Body Query Request</h5>
                <p className="text-[10px] text-zinc-550 mt-1">This endpoint parses state internally without requiring a parameter payload body.</p>
              </div>
            )}

            <div className="mt-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-amber-300 font-mono bg-amber-500/10 px-2.5 py-1 rounded border border-amber-500/20 uppercase tracking-wider font-bold">
                  SECURE API GATEWAY ACTIVE
                </span>
              </div>
              <button
                onClick={executeCall}
                disabled={isLoading}
                className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs px-4 py-2 rounded font-mono cursor-pointer transition-all disabled:opacity-40"
              >
                <Play className="h-3 w-3 fill-white" />
                {isLoading ? 'COMMUNICATING...' : 'EXECUTE ROUTE CALL'}
              </button>
            </div>
          </div>

          {/* Response payload viewer */}
          <div className="bg-[#0B0B0E] border border-zinc-900 rounded-lg p-4 font-mono">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-2 mb-3 text-xs text-zinc-500">
              <span className="flex items-center gap-1">
                <Code className="h-3.5 w-3.5 text-indigo-400" />
                CURL OUTPUT STREAM RESPONSE
              </span>
              {stats && (
                <span className="text-[10px]">
                  Response: <span className="text-emerald-400">{stats.status}</span> ({stats.time}ms)
                </span>
              )}
            </div>

            <div className="max-h-[200px] overflow-y-auto text-[11px] text-emerald-400/90 leading-relaxed whitespace-pre font-mono">
              {response ? response : (
                <span className="text-zinc-600 italic">// Click execute route call above to trigger active live telemetry diagnostics</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
