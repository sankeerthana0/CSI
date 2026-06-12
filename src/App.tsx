import React, { useState, useEffect } from 'react';
import { 
  ThreatLog, 
  KnowledgeDocument, 
  AgentWorkflowRun, 
  LangGraphNodeId, 
  WorkflowStepLog 
} from './types';
import { LangGraphViewer } from './components/LangGraphViewer';
import { VectorDbManager } from './components/VectorDbManager';
import { FastApiSandbox } from './components/FastApiSandbox';
import { EvaluationAudit } from './components/EvaluationAudit';

import { 
  Search, Shield, Server, Database, Sparkles, Terminal, Activity, 
  AlertOctagon, CheckCircle2, ChevronRight, Clock, RefreshCw, 
  Settings, Bot, HelpCircle, FileText, Send, AlertTriangle, ShieldCheck, Play
} from 'lucide-react';

export default function App() {
  // Logs and docs states
  const [threatLogs, setThreatLogs] = useState<ThreatLog[]>([]);
  const [knowledgeBase, setKnowledgeBase] = useState<KnowledgeDocument[]>([]);
  const [runs, setRuns] = useState<AgentWorkflowRun[]>([]);
  const [systemHealth, setSystemHealth] = useState<any>(null);

  // Active inputs states
  const [query, setQuery] = useState('Analyze LockBit Ransomware activity from suspicious Powershell logs and recommend countermeasures');
  const [selectedLogId, setSelectedLogId] = useState<string>('');
  
  // New Ingress Log states
  const [logTitle, setLogTitle] = useState('');
  const [logContent, setLogContent] = useState('');
  const [logSeverity, setLogSeverity] = useState('MEDIUM');
  const [logIps, setLogIps] = useState('');
  const [logTechniques, setLogTechniques] = useState('');
  const [isIngesting, setIsIngesting] = useState(false);

  // Workflow orchestration state
  const [activeRun, setActiveRun] = useState<AgentWorkflowRun | null>(null);
  const [activeNode, setActiveNode] = useState<LangGraphNodeId>('idle');
  const [isOrchestrating, setIsOrchestrating] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState<'analyst' | 'ciso' | 'alert' | 'audit'>('analyst');
  
  // Loading & general states
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  // Fetch initial telemetry
  const fetchData = async () => {
    setIsLoading(true);
    try {
      const [logsRes, docsRes, healthRes, runsRes] = await Promise.all([
        fetch('/api/threat-logs'),
        fetch('/api/rag/documents'),
        fetch('/api/health'),
        fetch('/api/evaluation/history')
      ]);

      const logs = await logsRes.json();
      const docs = await docsRes.json();
      const health = await healthRes.json();
      const historicalRuns = await runsRes.json();

      setThreatLogs(logs);
      setKnowledgeBase(docs);
      setSystemHealth(health);
      setRuns(historicalRuns);

      // Pre-select the latest logs matching LockBit defaults
      if (logs.length > 0 && !selectedLogId) {
        setSelectedLogId(logs[0].id);
      }
    } catch (e) {
      console.error("Error loading system metrics:", e);
      setErrorMessage("Network issue connecting to standard FastAPI microservice simulator.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Manual Ingestion of customized Threat Event Logs
  const handleIngestLog = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!logTitle || !logContent) return;

    setIsIngesting(true);
    setErrorMessage('');
    try {
      const parsedIps = logIps.split(',').map(s => s.trim()).filter(Boolean);
      const parsedTechs = logTechniques.split(',').map(s => s.trim()).filter(Boolean);

      const response = await fetch('/api/ingest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: logTitle,
          content: logContent,
          severity: logSeverity,
          techniques: parsedTechs,
          ips: parsedIps
        })
      });

      const result = await response.json();
      if (result.status === "success") {
        setLogTitle('');
        setLogContent('');
        setLogSeverity('MEDIUM');
        setLogIps('');
        setLogTechniques('');
        fetchData();
      } else {
        setErrorMessage(result.error || "Event ingestion failure");
      }
    } catch (err: any) {
      setErrorMessage(err.message || "Network ingestion fault");
    } finally {
      setIsIngesting(false);
    }
  };

  // Add a document directly into FAISS RAG Context vector index
  const handleAddRagDoc = async (doc: { title: string; text: string; source: string; tags: string[] }) => {
    const response = await fetch('/api/rag/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(doc)
    });
    const result = await response.json();
    if (result.status === "success") {
      fetchData();
    } else {
      throw new Error(result.error || "Failed to index intel briefings");
    }
  };

  // Run LangGraph system orchestrator
  const handleOrchestrate = async (queryOverride?: string) => {
    const activeQuery = queryOverride || query;
    if (!activeQuery) return;

    setIsOrchestrating(true);
    setErrorMessage('');
    setActiveRun(null);
    setActiveNode('idle');

    // Simulate Step-By-Step LangGraph State Machine transition delay for beautiful user visualization
    const workflowSteps: LangGraphNodeId[] = ['ingest', 'retrieve', 'analysis', 'summarize', 'alert', 'evaluate', 'complete'];
    
    let currentStepIndex = 0;
    const interval = setInterval(() => {
      if (currentStepIndex < workflowSteps.length - 1) {
        setActiveNode(workflowSteps[currentStepIndex]);
        currentStepIndex++;
      } else {
        clearInterval(interval);
      }
    }, 1100);

    try {
      const response = await fetch('/api/agents/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: activeQuery,
          customLogId: selectedLogId || undefined
        })
      });

      const runResult: AgentWorkflowRun = await response.json();
      
      // Stop synthetic transition loops once real data hits to display official payload state
      clearInterval(interval);
      
      setActiveRun(runResult);
      setActiveNode('complete');
      fetchData(); // Sync logs
    } catch (err: any) {
      clearInterval(interval);
      setActiveNode('idle');
      setErrorMessage(err.message || "Failed running Multi-agent worker nodes");
    } finally {
      setIsOrchestrating(false);
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-950/40 text-red-400 border-red-500/20';
      case 'HIGH': return 'bg-amber-950/40 text-amber-500 border-amber-500/20';
      case 'MEDIUM': return 'bg-zinc-800/50 text-zinc-300 border-zinc-700/50';
      default: return 'bg-zinc-900/60 text-zinc-400 border-zinc-800';
    }
  };

  return (
    <div className="min-h-screen bg-[#09090B] text-zinc-300 font-sans selection:bg-indigo-500/30 selection:text-white pb-16 bg-[radial-gradient(#1c1c21_1px,transparent_1px)] bg-[size:40px_40px]">
      
      {/* Primary Cyber Security Masthead bar */}
      <header className="border-b border-zinc-800 bg-[#0E0E11]/90 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 bg-indigo-600 rounded flex items-center justify-center text-white shadow-[0_0_15px_rgba(99,102,241,0.3)]">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-mono font-bold tracking-widest text-indigo-400">
                  COSMIC SHIELD INTELLIGENCE
                </h1>
                <span className="text-[9px] bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2 py-0.5 rounded-full font-mono font-bold animate-pulse">
                  SYSTEM ONLINE
                </span>
              </div>
              <h2 className="text-xl font-bold tracking-tight text-white mt-0.5">
                Enterprise Multi-Agent Cyber Threat Intelligence Hub
              </h2>
            </div>
          </div>

          {/* Quick Metrics display headers */}
          {systemHealth && (
            <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
              <div className="bg-zinc-950 p-2.5 rounded border border-zinc-800 flex flex-col">
                <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-bold">GEMINI LLM ENGINE</span>
                <span className={`font-bold mt-0.5 ${systemHealth.gemini_key_active ? 'text-emerald-400' : 'text-amber-500'}`}>
                  {systemHealth.gemini_key_active ? 'Active (Studio-3.5)' : 'Heuristic Fallback'}
                </span>
              </div>
              <div className="bg-zinc-950 p-2.5 rounded border border-zinc-800 flex flex-col">
                <span className="text-[10px] text-zinc-500 uppercase tracking-widest font-bold font-mono">FAISS-RAG INDEX</span>
                <span className="text-indigo-400 font-bold mt-0.5">{systemHealth.vector_indexed_docs_count} Documents</span>
              </div>
              <button 
                onClick={fetchData}
                className="p-2.5 bg-zinc-900 border border-zinc-800 text-zinc-300 hover:text-white rounded hover:bg-zinc-800 transition-all cursor-pointer h-full flex items-center justify-center"
                title="Refresh Status Diagnostics"
              >
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin text-indigo-400' : ''}`} />
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 mt-8 space-y-8 relative z-10">
        
        {/* Error notification */}
        {errorMessage && (
          <div className="bg-red-950/20 border border-red-500/20 rounded-xl p-4 flex items-start gap-3 text-red-200">
            <AlertTriangle className="h-5 w-5 text-red-400 mt-0.5" />
            <div>
              <h4 className="text-sm font-semibold font-mono">System Exception Detected</h4>
              <p className="text-xs text-red-300 mt-1">{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Section 1: Ingestion Intake & Multi-Agent Main Console triggers */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          
          {/* Left Column: Quick Logs Stream Selector & Manual Log Ingestion */}
          <div className="lg:col-span-4 space-y-6">
            
            {/* Direct selection list */}
            <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <h3 className="text-xs font-mono font-bold text-zinc-400 mb-4 flex items-center gap-1.5 border-b border-zinc-800 pb-2">
                <Activity className="h-4 w-4 text-indigo-400" /> ACTIVE EVENT INGESTION STREAM
              </h3>

              <div className="space-y-3 max-h-[240px] overflow-y-auto pr-1">
                {threatLogs.map(log => (
                  <div
                    key={log.id}
                    onClick={() => {
                      setSelectedLogId(log.id);
                      // Suggest customized threat query tailored around log context
                      if (log.title.includes("HR-SRV-90")) {
                        setQuery("Analyze LockBit Ransomware activity from suspicious Powershell logs and recommend countermeasures");
                      } else if (log.title.includes("Tor relay IP")) {
                        setQuery("Describe Tor exit relay connections from firewall log 193.23.45.166");
                      } else {
                        setQuery(`Perform multi-agent strategic audit regarding event "${log.title}"`);
                      }
                    }}
                    className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${
                      selectedLogId === log.id 
                        ? 'bg-zinc-800/40 border-indigo-500/60 shadow-[0_0_15px_rgba(99,102,241,0.15)] ring-1 ring-indigo-500/25' 
                        : 'bg-zinc-900/20 border-zinc-800/50 hover:bg-zinc-800/30 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1.5">
                      <span className="text-[10px] font-mono text-zinc-500">{log.id}</span>
                      <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${getSeverityBadgeClass(log.parsedMetadata.severity)}`}>
                        {log.parsedMetadata.severity}
                      </span>
                    </div>
                    <h4 className="text-sm font-semibold text-white line-clamp-1">{log.title}</h4>
                    <span className="text-[10px] text-zinc-400 font-mono mt-1 block">Src: {log.source}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Manual Ingestion Form */}
            <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-5 shadow-2xl">
              <h3 className="text-xs font-mono font-bold text-zinc-400 mb-4 flex items-center gap-1.5 border-b border-zinc-800 pb-2">
                <Server className="h-4 w-4 text-indigo-400" /> INGEST RAW THREAT / SYSLOG PAYLOAD
              </h3>

              <form onSubmit={handleIngestLog} className="space-y-3.5">
                <div>
                  <label className="block text-[10px] font-mono text-zinc-500 mb-1">EVENT TITLE / FLAG</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Critical Exfiltration Trigger on DB-01"
                    value={logTitle}
                    onChange={e => setLogTitle(e.target.value)}
                    className="w-full bg-zinc-950 border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded p-2 text-xs text-zinc-200"
                  />
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-500 mb-1">SEVERITY RATIO</label>
                    <select
                      value={logSeverity}
                      onChange={e => setLogSeverity(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded p-2 text-xs text-zinc-300"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-500 mb-1">SOURCE ELEMENT</label>
                    <input
                      type="text"
                      placeholder="e.g. Audit-Daemon / WAF"
                      onChange={e => setLogIps(e.target.value)} // Reusing fields
                      className="w-full bg-zinc-950 border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded p-2 text-xs text-zinc-200"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-500 mb-1">AFFECTED IPS</label>
                    <input
                      type="text"
                      placeholder="185.120.34.12"
                      value={logIps}
                      onChange={e => setLogIps(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded p-2 text-xs text-zinc-200 font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] font-mono text-zinc-500 mb-1">MITRE CODE TTP</label>
                    <input
                      type="text"
                      placeholder="T1490, T1059"
                      value={logTechniques}
                      onChange={e => setLogTechniques(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded p-2 text-xs text-zinc-200 font-mono"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono text-zinc-500 mb-1">RAW SYSLOG / PAYLOAD CONTENT</label>
                  <textarea
                    required
                    rows={3}
                    placeholder="powershell.exe -Command '...' "
                    value={logContent}
                    onChange={e => setLogContent(e.target.value)}
                    className="w-full bg-zinc-950 border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded p-2 text-xs text-zinc-200 font-mono text-indigo-400"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isIngesting}
                  className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold font-mono text-xs p-2.5 rounded transition-all cursor-pointer disabled:opacity-40"
                >
                  {isIngesting ? 'INGESTING REPORT...' : 'INGEST EVENT LOG'}
                </button>
              </form>
            </div>
          </div>

          {/* Right Column: Prompts Trigger Bar & Agent Processing Nodes Trace */}
          <div className="lg:col-span-8 space-y-6">
            
            {/* Orchestration trigger board */}
            <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-6 shadow-2xl relative">
              <div className="absolute top-0 right-0 w-24 h-24 bg-indigo-500/5 rounded-full blur-2xl pointer-events-none" />

              <h3 className="text-md font-mono font-bold text-zinc-200 mb-2 flex items-center gap-1.5">
                <Bot className="h-5 w-5 text-indigo-400 animate-pulse" /> TARGET ANALYSIS DEPLOYMENT
              </h3>
              <p className="text-xs text-zinc-400 mb-4 leading-relaxed">
                Formulate intelligence queries or evaluate active threats. The orchestrator will trigger the LangGraph flow, parse vector metrics, and run critic scoring pipelines.
              </p>

              {/* Sample Quick Prompts buttons */}
              <div className="flex flex-wrap gap-2 mb-4">
                <button
                  onClick={() => {
                    setQuery("Analyze LockBit Ransomware activity from suspicious Powershell logs and recommend countermeasures");
                    setSelectedLogId("log-101");
                  }}
                  className="bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-[10px] font-mono px-2.5 py-1.5 rounded cursor-pointer transition-all text-zinc-300"
                >
                  Scenario A: LockBit Shadow Erasure
                </button>
                <button
                  onClick={() => {
                    setQuery("Describe Tor exit relay connections from firewall log 193.23.45.166");
                    setSelectedLogId("log-102");
                  }}
                  className="bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-[10px] font-mono px-2.5 py-1.5 rounded cursor-pointer transition-all text-zinc-300"
                >
                  Scenario B: Cozy Bear / Tor C2 Relay
                </button>
                <button
                  onClick={() => {
                    setQuery("CVE-2026-9012 unauthenticated remote command execution intrusion evaluation");
                    setSelectedLogId("log-103");
                  }}
                  className="bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 text-[10px] font-mono px-2.5 py-1.5 rounded cursor-pointer transition-all text-zinc-300"
                >
                  Scenario C: Spring Boot CVE RCE
                </button>
              </div>

              {/* Main query interaction group */}
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-grow">
                  <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4.5 w-4.5 text-zinc-500" />
                  <input
                    type="text"
                    value={query}
                    onChange={e => setQuery(e.target.value)}
                    placeholder="Enter security audit terms, IP pointers, or threat actors catalog..."
                    className="w-full bg-zinc-950 border border-zinc-800 focus:border-indigo-500 focus:outline-none rounded-lg pl-10 pr-4 py-3 text-xs text-zinc-200"
                  />
                </div>
                <button
                  disabled={isOrchestrating}
                  onClick={() => handleOrchestrate()}
                  className="bg-indigo-600 hover:bg-indigo-500 text-white font-mono font-bold text-xs px-6 py-3 rounded-lg flex items-center justify-center gap-2 transition-all cursor-pointer shadow-lg shadow-indigo-950/20 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5 fill-white text-white" />
                  {isOrchestrating ? 'ORCHESTRATING...' : 'RUN ORCHESTRATOR'}
                </button>
              </div>
            </div>

            {/* Visual LangGraph transition dashboard node */}
            <LangGraphViewer stepLogs={activeRun?.stepLogs || []} activeNode={activeNode} />
          </div>
        </div>

        {/* Section 2: Results Terminal & Agent Node Outputs Tabs */}
        {(activeRun || runs.length > 0) && (
          <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-6 shadow-2xl space-y-6">
            
            {/* Header info */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
              <div>
                <span className="text-[10px] font-mono text-indigo-400 font-bold bg-indigo-500/10 px-2.5 py-1 rounded border border-indigo-500/20 uppercase tracking-wider">
                  SYSTEM AUDIT HISTORIC TRACE
                </span>
                <h3 className="text-md font-bold text-white mt-1.5 flex items-center gap-1.5">
                  <Terminal className="h-4.5 w-4.5 text-indigo-400" />
                  CTI MULTI-AGENT SYNTHESIS RESULT LOGS
                </h3>
              </div>
              
              <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
                <span className="text-xs font-mono text-zinc-400">SELECT RUN HISTORY:</span>
                <select
                  value={activeRun?.id || ''}
                  onChange={e => {
                    const selected = runs.find(r => r.id === e.target.value);
                    if (selected) {
                      setActiveRun(selected);
                    }
                  }}
                  className="bg-zinc-950 border border-zinc-800 text-xs text-zinc-300 font-mono px-3 py-1.5 rounded focus:outline-none focus:border-indigo-500"
                >
                  {runs.map(r => (
                    <option key={r.id} value={r.id}>
                      {r.id === activeRun?.id ? '[ACTIVE] ' : ''}{r.inputQuery.substring(0, 32)}... ({new Date(r.createdAt).toLocaleTimeString()})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* If we have an active or selected run */}
            {activeRun && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                
                {/* Left Mini details: matching logs and documents ingested */}
                <div className="lg:col-span-4 space-y-4 font-mono">
                  <div className="bg-zinc-950/80 p-4 rounded-lg border border-zinc-800/80">
                    <span className="text-[10px] text-zinc-500 font-bold text-xs block mb-2 tracking-wider">CONTEXT RETRIEVAL (RAG)</span>
                    <div className="space-y-2">
                      <div className="text-[11px] text-zinc-400">
                        Logs Analyzed: <span className="text-indigo-400">{activeRun.logsAnalyzed?.length || 0} event payloads</span>
                      </div>
                      <div className="text-[11px] text-zinc-400">
                        ChromaDB Matches: <span className="text-emerald-400">{activeRun.retrievedDocs?.length || 0} intelligence briefings</span>
                      </div>
                      <div className="text-[10px] text-zinc-500 mt-2 border-t border-zinc-800 pt-2 bg-zinc-950/20">
                        Target IPs found: <span className="text-zinc-300">{activeRun.analysis?.indicatorsOfCompromise.join(', ') || 'None'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Evaluation Score Highlights widget */}
                  {activeRun.evaluation && (
                    <div className="bg-zinc-950/80 p-4 rounded-lg border border-zinc-800/80">
                      <span className="text-[10px] text-zinc-500 font-bold text-xs block mb-2 tracking-wider">EVALUATION METRICS</span>
                      <div className="space-y-2">
                        <div className="flex justify-between text-[11px]">
                          <span className="text-zinc-400">Fidelity Score:</span>
                          <span className="text-emerald-400 font-bold">{activeRun.evaluation.faithfulnessScore}%</span>
                        </div>
                        <div className="flex justify-between text-[11px]">
                          <span className="text-zinc-400">Accuracy Score:</span>
                          <span className="text-indigo-400 font-bold">{activeRun.evaluation.accuracyScore}%</span>
                        </div>
                        <div className="flex justify-between text-[11px]">
                          <span className="text-zinc-400">Relevance Score:</span>
                          <span className="text-amber-500 font-bold">{activeRun.evaluation.relevanceScore}%</span>
                        </div>
                        <div className="pt-2 border-t border-zinc-800 text-center">
                          <span className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">VALIDATED CONFIDENCE INDEX</span>
                          <div className="text-lg font-black text-white mt-0.5">{activeRun.evaluation.overallScore}%</div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                {/* Right Tabs: Dynamic Response Views of Strategic Analysis, Summarizer, and SOAR outputs */}
                <div className="lg:col-span-8 space-y-4">
                  
                  {/* Tab switches */}
                  <div className="flex border-b border-zinc-800 overflow-x-auto">
                    <button
                      onClick={() => setActiveSubTab('analyst')}
                      className={`px-4 py-2.5 text-xs font-mono font-bold border-b-2 cursor-pointer transition-all whitespace-nowrap ${
                        activeSubTab === 'analyst' 
                          ? 'border-indigo-500 text-indigo-400 bg-zinc-900/30' 
                          : 'border-transparent text-zinc-500 hover:text-zinc-200'
                      }`}
                    >
                      STRATEGIC COGNITIVE ANALYSIS
                    </button>
                    <button
                      onClick={() => setActiveSubTab('ciso')}
                      className={`px-4 py-2.5 text-xs font-mono font-bold border-b-2 cursor-pointer transition-all whitespace-nowrap ${
                        activeSubTab === 'ciso' 
                          ? 'border-indigo-500 text-indigo-400 bg-zinc-900/30' 
                          : 'border-transparent text-zinc-500 hover:text-zinc-200'
                      }`}
                    >
                      CISO SYSTEM EXECUTIVE SUMMARY
                    </button>
                    <button
                      onClick={() => setActiveSubTab('alert')}
                      className={`px-4 py-2.5 text-xs font-mono font-bold border-b-2 cursor-pointer transition-all whitespace-nowrap ${
                        activeSubTab === 'alert' 
                          ? 'border-indigo-500 text-indigo-400 bg-zinc-900/30' 
                          : 'border-transparent text-zinc-500 hover:text-zinc-200'
                      }`}
                    >
                      SIEM / WEBHOOKS PAYLOAD
                    </button>
                    <button
                      onClick={() => setActiveSubTab('audit')}
                      className={`px-4 py-2.5 text-xs font-mono font-bold border-b-2 cursor-pointer transition-all whitespace-nowrap ${
                        activeSubTab === 'audit' 
                          ? 'border-indigo-500 text-indigo-400 bg-zinc-900/30' 
                          : 'border-transparent text-zinc-500 hover:text-zinc-200'
                      }`}
                    >
                      EVALUATION CRITICISM
                    </button>
                  </div>

                  {/* Rendering Tab contents */}
                  <div className="bg-zinc-950 border border-zinc-800/80 rounded-lg p-5">
                    
                    {activeSubTab === 'analyst' && activeRun.analysis && (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
                          <span className="text-[10px] font-mono text-indigo-400 font-bold bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                            AGENT NAME: ADVANCED_INTEL_ANALYST
                          </span>
                          <span className="text-xs text-zinc-400 font-mono">
                            Assigned Threat Severity Score: <span className="text-amber-500 font-bold">{activeRun.analysis.severityScore}/10</span>
                          </span>
                        </div>

                        <div>
                          <span className="text-[10px] font-mono text-zinc-500 block mb-1 uppercase tracking-widest font-bold">DIAGNOSED ATTACK THREAT VECTOR</span>
                          <p className="text-xs text-zinc-200 leading-relaxed font-mono">
                            {activeRun.analysis.threatVector}
                          </p>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                          <div>
                            <span className="text-[10px] font-mono text-zinc-500 block mb-1.5 uppercase tracking-widest font-bold">MUTUALLY ATTRIBUTED GROUPS / APTS</span>
                            <div className="flex flex-wrap gap-1.5">
                              {activeRun.analysis.associatedActors.map(actor => (
                                <span key={actor} className="text-[10.5px] font-mono bg-zinc-900 border border-zinc-800 text-zinc-300 px-2 py-0.5 rounded">
                                  {actor}
                                </span>
                              ))}
                            </div>
                          </div>
                          <div>
                            <span className="text-[10px] font-mono text-zinc-500 block mb-1.5 uppercase tracking-widest font-bold">TARGET SYSTEM SCOPE</span>
                            <div className="flex flex-wrap gap-1.5">
                              {activeRun.analysis.targetSystems.map(sys => (
                                <span key={sys} className="text-[10.5px] font-mono bg-zinc-900 border border-zinc-800 text-zinc-300 px-2 py-0.5 rounded">
                                  {sys}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>

                        <div>
                          <span className="text-[10px] font-mono text-zinc-500 block mb-1.5 uppercase tracking-widest font-bold">TRACKED INTRUSION METHODS</span>
                          <div className="flex flex-wrap gap-1.5">
                            {activeRun.analysis.methodologies.map(m => (
                              <span key={m} className="text-[10.5px] font-mono bg-zinc-900 border border-zinc-800 text-indigo-400 px-2.5 py-1 rounded">
                                {m}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div>
                          <span className="text-[10px] font-mono text-zinc-500 block mb-2 uppercase tracking-widest font-bold">OPERATOR REMEDIATION BLUEPRINT</span>
                          <ul className="space-y-1.5 font-mono text-xs">
                            {activeRun.analysis.mitigations.map((mit, idx) => (
                              <li key={idx} className="flex items-start gap-2 text-zinc-300">
                                <ChevronRight className="h-4 w-4 text-indigo-400 mt-0.5 flex-shrink-0" />
                                <span>{mit}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    )}

                    {activeSubTab === 'ciso' && activeRun.summary && (
                      <div className="space-y-4">
                        <div className="border-b border-zinc-900 pb-3">
                          <span className="text-[10px] font-mono text-indigo-400 font-bold bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                            AGENT NAME: CISO_KEYNOTE_COMMS
                          </span>
                          <h4 className="text-md font-bold text-white mt-2">Headline: "{activeRun.summary.headline}"</h4>
                        </div>

                        <div>
                          <span className="text-[10px] font-mono text-zinc-500 block mb-1 uppercase tracking-widest font-bold">CISO SYSTEMS AUDIT BRIEF</span>
                          <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                            {activeRun.summary.executiveSummary}
                          </p>
                        </div>

                        <div>
                          <span className="text-[10px] font-mono text-zinc-500 block mb-2 uppercase tracking-widest font-bold">TECHNICAL REMEDIATION METRICS</span>
                          <div className="space-y-2">
                            {activeRun.summary.keyTakeaways.map((takeaway, index) => (
                              <div key={index} className="flex items-start gap-2 bg-zinc-900/40 border border-zinc-800/60 p-3 rounded-lg">
                                <CheckCircle2 className="h-4 w-4 text-emerald-400 mt-0.5 flex-shrink-0" />
                                <span className="text-xs text-zinc-300 leading-relaxed font-mono">{takeaway}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    )}

                    {activeSubTab === 'alert' && activeRun.alert && (
                      <div className="space-y-4 font-mono">
                        <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
                          <span className="text-[10px] font-mono text-indigo-400 font-bold bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
                            AGENT NAME: SOAR_INTEGRATION_TRIGGER
                          </span>
                          <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded border ${
                            activeRun.alert.alertTriggered ? 'bg-indigo-950/40 text-indigo-300 border-indigo-500/30' : 'bg-zinc-900 text-zinc-500 border-zinc-800'
                          }`}>
                            {activeRun.alert.alertTriggered ? 'TRIGGER: CONDITIONS PASSED' : 'TRIGGER: CONDITIONS HALTED'}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 gap-4 text-xs">
                          <div>
                            <span className="text-[10px] text-zinc-500 block mb-1 uppercase tracking-widest font-bold">SIEM CONSOLE PRIORITY</span>
                            <span className="text-zinc-200 font-bold">{(activeRun.alert.priority || 'MEDIUM').toUpperCase()}</span>
                          </div>
                          <div>
                            <span className="text-[10px] text-zinc-500 block mb-1 uppercase tracking-widest font-bold">MAPPED REMEDIATION PLAYBOOK</span>
                            <span className="text-zinc-200 font-bold">{activeRun.alert.suggestedAction || 'Incident Playbook Default'}</span>
                          </div>
                        </div>

                        <div>
                          <span className="text-[10px] text-zinc-500 block mb-1 uppercase tracking-widest font-bold">SIEM WEBHOOK PAYLOAD TEMPLATE (.JSON)</span>
                          <pre className="bg-[#0B0B0E] p-3 rounded border border-zinc-800 text-[10px] text-amber-500 overflow-x-auto whitespace-pre">
                            {activeRun.alert.payloadTemplate}
                          </pre>
                        </div>
                      </div>
                    )}

                    {activeSubTab === 'audit' && activeRun.evaluation && (
                      <EvaluationAudit evaluation={activeRun.evaluation} latencyMs={activeRun.latencyMs} />
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Section 3: RAG Core indexed Documents database & OpenAPI Sandbox split */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <VectorDbManager documents={knowledgeBase} onAddDocument={handleAddRagDoc} isLoading={isLoading} />
          <FastApiSandbox onRunQuery={handleOrchestrate} onIngestLog={async (log) => {}} />
        </div>

      </main>

      <footer className="max-w-7xl mx-auto px-4 mt-16 pt-8 border-t border-zinc-800 text-center text-xs text-zinc-500 font-mono">
        <p>Enterprise Cyber Threat Intelligence Agent Console  |  Designed using React + Express + Gemini SDK</p>
        <p className="mt-1 text-zinc-600">Secure pipeline validated under automated LangGraph agent evaluation protocols.</p>
      </footer>
    </div>
  );
}
