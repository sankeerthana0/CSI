import React from 'react';
import { LangGraphNodeId, WorkflowStepLog } from '../types';
import { Play, CheckCircle2, ShieldAlert, Radio, ArrowRight, CornerRightDown, Server, Database, Brain, Sparkles, FileText, Activity } from 'lucide-react';

interface LangGraphViewerProps {
  stepLogs: WorkflowStepLog[];
  activeNode: LangGraphNodeId;
}

export const LangGraphViewer: React.FC<LangGraphViewerProps> = ({ stepLogs, activeNode }) => {
  const nodes = [
    {
      id: 'ingest' as LangGraphNodeId,
      label: 'Ingestion Node',
      description: 'Parses raw syslogs & manual threat report inputs',
      icon: Server,
      color: 'from-blue-600/30 to-blue-500/10 border-blue-500/50 text-blue-400'
    },
    {
      id: 'retrieve' as LangGraphNodeId,
      label: 'FAISS/RAG Node',
      description: 'Cross-checks in-memory vector index for actor briefs',
      icon: Database,
      color: 'from-purple-600/30 to-purple-500/10 border-purple-500/50 text-purple-400'
    },
    {
      id: 'analysis' as LangGraphNodeId,
      label: 'Intel Analyst Agent',
      description: 'Diagnoses threat vectors, targets & tactics via Gemini',
      icon: Brain,
      color: 'from-amber-600/30 to-amber-500/10 border-amber-500/50 text-amber-400'
    },
    {
      id: 'summarize' as LangGraphNodeId,
      label: 'Executive Summarizer',
      description: 'Prepares CISO summaries and tactical metrics',
      icon: FileText,
      color: 'from-teal-600/30 to-teal-500/10 border-teal-500/50 text-teal-400'
    },
    {
      id: 'alert' as LangGraphNodeId,
      label: 'SIEM Alerting Agent',
      description: 'Drafts down-line webhooks & webhook formats',
      icon: ShieldAlert,
      color: 'from-red-600/30 to-red-500/10 border-red-500/50 text-red-400'
    },
    {
      id: 'evaluate' as LangGraphNodeId,
      label: 'Critic Evaluator Node',
      description: 'Validates correctness, faithfulness & relevance',
      icon: Sparkles,
      color: 'from-emerald-600/30 to-emerald-500/10 border-emerald-500/50 text-emerald-400'
    }
  ];

  const getStepStatus = (id: LangGraphNodeId) => {
    const matched = stepLogs.find(log => log.nodeId === id);
    if (activeNode === id) return 'running';
    if (matched) return matched.status;
    return 'pending';
  };

  return (
    <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-6 shadow-2xl relative overflow-hidden">
      {/* Visual background grids */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#27272a08_1px,transparent_1px),linear-gradient(to_bottom,#27272a08_1px,transparent_1px)] bg-[size:14px_24px] pointer-events-none" />
      
      <div className="relative flex items-center justify-between border-b border-zinc-800 pb-4 mb-6">
        <div>
          <h3 className="text-md font-mono font-semibold text-white flex items-center gap-2">
            <Activity className="h-4 w-4 text-indigo-400 animate-pulse" />
            LANGGRAPH MULTI-AGENT ORCHESTRATION PIPELINE
          </h3>
          <p className="text-xs text-zinc-400 mt-1">
            Real-time visual trace of state transfers, agent logic nodes, and control boundaries.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono bg-zinc-950 px-3 py-1.5 rounded-md border border-zinc-800">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-zinc-300">ACTIVE HANDLERS: READY</span>
        </div>
      </div>

      {/* Grid of Nodes */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative z-10">
        {nodes.map((node, i) => {
          const status = getStepStatus(node.id);
          const Icon = node.icon;
          
          return (
            <div key={node.id} className="relative">
              <div 
                className={`flex flex-col h-full rounded-lg border p-4 bg-gradient-to-br transition-all duration-300 ${
                  status === 'running' 
                    ? 'ring-2 ring-indigo-500/70 shadow-[0_0_15px_rgba(99,102,241,0.15)] scale-[1.02] border-indigo-500 bg-indigo-950/10'
                    : status === 'completed'
                    ? 'border-emerald-500/40 bg-zinc-900/60 opacity-95'
                    : 'border-zinc-800/60 bg-zinc-950/40 opacity-60'
                }`}
              >
                {/* Node Title Header */}
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <div className={`p-1.5 rounded-md bg-zinc-950 border border-zinc-800 ${
                      status === 'running' ? 'text-indigo-400' : 'text-zinc-400'
                    }`}>
                      <Icon className="h-4.5 w-4.5" />
                    </div>
                    <span className="text-xs font-mono text-zinc-500">NODE {i + 1}</span>
                  </div>

                  {/* Status Indicator */}
                  <div>
                    {status === 'running' && (
                      <span className="flex items-center gap-1 text-[10px] bg-indigo-950/45 text-indigo-300 px-2 py-0.5 rounded border border-indigo-500/30 font-mono animate-pulse">
                        <Radio className="h-2.5 w-2.5 animate-spin" /> RUNNING
                      </span>
                    )}
                    {status === 'completed' && (
                      <span className="flex items-center gap-0.5 text-[10px] bg-emerald-950/20 text-emerald-400 px-2 py-0.5 rounded border border-emerald-500/20 font-mono">
                        <CheckCircle2 className="h-2.5 w-2.5 text-emerald-400" /> PASS
                      </span>
                    )}
                    {status === 'pending' && (
                      <span className="text-[10px] bg-zinc-900/40 text-zinc-500 px-2 py-0.5 rounded border border-zinc-800 font-mono">
                        IDLE
                      </span>
                    )}
                  </div>
                </div>

                <h4 className="text-sm font-semibold text-white mt-1">{node.label}</h4>
                <p className="text-xs text-zinc-400 mt-1.5 leading-relaxed flex-grow">{node.description}</p>

                {/* Specific Node Preview Telemetry block */}
                {status === 'completed' && (
                  <div className="mt-3 pt-2 border-t border-zinc-800/60 font-mono text-[10px] text-zinc-500">
                    {node.id === 'ingest' && (
                      <span className="text-indigo-400">
                        {stepLogs.find(l => l.nodeId === 'ingest')?.payload?.parsedLogsCount || 0} event payloads extracted
                      </span>
                    )}
                    {node.id === 'retrieve' && (
                      <span className="text-indigo-400">
                        Context score: max {stepLogs.find(l => l.nodeId === 'retrieve')?.payload?.matchingDocs?.[0]?.relevanceScore || "0.00"}
                      </span>
                    )}
                    {node.id === 'analysis' && (
                      <span className="text-indigo-400">
                        Severity class: {stepLogs.find(l => l.nodeId === 'analysis')?.payload?.severityScore || 0}/10 CSOC
                      </span>
                    )}
                    {node.id === 'summarize' && (
                      <span className="text-indigo-400">
                        Takeaways structured: {stepLogs.find(l => l.nodeId === 'summarize')?.payload?.keyTakeaways?.length || 0} items
                      </span>
                    )}
                    {node.id === 'alert' && (
                      <span className="text-red-400 font-semibold">
                        Alert: {(stepLogs.find(l => l.nodeId === 'alert')?.payload?.priority || 'NONE').toUpperCase()}
                      </span>
                    )}
                    {node.id === 'evaluate' && (
                      <span className="text-emerald-400 font-bold">
                        Critic score: {stepLogs.find(l => l.nodeId === 'evaluate')?.payload?.overallScore || 0}% Acc
                      </span>
                    )}
                  </div>
                )}
              </div>

              {/* Edge Connecting Arrow */}
              {i < nodes.length - 1 && i % 3 !== 2 && (
                <div className="hidden md:flex items-center justify-center absolute -right-3.5 top-1/2 -translate-y-1/2 z-20 text-zinc-700">
                  <ArrowRight className="h-4 w-4" />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Control Status Footer */}
      <div className="mt-6 pt-4 border-t border-zinc-800 flex flex-wrap gap-4 items-center justify-between text-xs font-mono">
        <span className="text-zinc-500">
          State Variables Passed: [Query, IngestedThreatPayload, ContextDocuments, AgentCalculations, EvaluatorFeedback]
        </span>
        <div className="flex items-center gap-2">
          <span className="text-zinc-500">Orchestrator:</span>
          <span className="px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-indigo-400 text-[10px]">
            LangGraph Router (TS-Engine)
          </span>
        </div>
      </div>
    </div>
  );
};
