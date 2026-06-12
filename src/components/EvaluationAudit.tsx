import React from 'react';
import { EvaluationResult } from '../types';
import { Sparkles, Trophy, CheckCircle, Info, ShieldCheck, Gauge } from 'lucide-react';

interface EvaluationAuditProps {
  evaluation?: EvaluationResult;
  latencyMs?: number;
}

export const EvaluationAudit: React.FC<EvaluationAuditProps> = ({ evaluation, latencyMs }) => {
  if (!evaluation) {
    return (
      <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-6 shadow-2xl text-center py-10">
        <Gauge className="h-10 w-10 text-zinc-600 mx-auto mb-3 animate-pulse" />
        <h4 className="text-md font-mono font-semibold text-zinc-400">Security Response Evaluation Standby</h4>
        <p className="text-xs text-zinc-500 mt-2 max-w-sm mx-auto leading-relaxed">
          The automated LangGraph validator runs on raw results after initial agent loops complete. Trigger an threat analysis to inspect evaluation results.
        </p>
      </div>
    );
  }

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-400';
    if (score >= 75) return 'text-indigo-400';
    if (score >= 50) return 'text-amber-400';
    return 'text-red-400';
  };

  const scores = [
    {
      label: 'Context Faithfulness',
      value: evaluation.faithfulnessScore,
      desc: 'Fidelity of generated attack details to matching threat records. Penalizes dynamic hallucinations.',
      color: 'from-emerald-500 to-emerald-450',
      bgColor: 'bg-zinc-950/45 border-zinc-850'
    },
    {
      label: 'Topic Relevance',
      value: evaluation.relevanceScore,
      desc: 'Direct alignment of remediation strategies and analysis to the operator query focus.',
      color: 'from-indigo-600 to-indigo-400',
      bgColor: 'bg-zinc-950/45 border-zinc-850'
    },
    {
      label: 'Technical Accuracy',
      value: evaluation.accuracyScore,
      desc: 'Precision matching known MITRE techniques, CVE coordinates, and indicators of compromise (IoCs).',
      color: 'from-indigo-500 to-purple-400',
      bgColor: 'bg-zinc-950/45 border-zinc-850'
    }
  ];

  return (
    <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-6 shadow-2xl relative overflow-hidden">
      {/* Decorative accent background glows */}
      <div className="absolute top-0 right-0 w-40 h-40 bg-indigo-500/5 rounded-full blur-3xl pointer-events-none" />

      <div className="flex border-b border-zinc-800 pb-4 mb-6 items-center justify-between gap-4">
        <div>
          <h3 className="text-md font-mono font-semibold text-white flex items-center gap-2">
            <Sparkles className="h-4.5 w-4.5 text-indigo-400" />
            LANGGRAPH EVALUATION PIPELINE & AUDIT OVERVIEW
          </h3>
          <p className="text-xs text-zinc-400 mt-1">
            Automated judge agent critiques technical outputs and scores semantic confidence parameters.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono bg-zinc-950 border border-zinc-800 px-3 py-1 text-zinc-300 rounded">
          <ShieldCheck className="h-4 w-4 text-indigo-400" />
          <span>JUDGE: {evaluation.evaluatorModel}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">
        {/* Big Overall Aggregated Score Gauge */}
        <div className="md:col-span-1 flex flex-col items-center justify-center p-4 bg-zinc-950/80 border border-zinc-800 rounded-lg text-center shadow-lg">
          <span className="text-[10px] font-mono text-zinc-500 font-bold tracking-wider">OVERALL SCORE</span>
          
          <div className="relative flex items-center justify-center mt-3 mb-2">
            <svg className="w-24 h-24 transform -rotate-90">
              <circle
                cx="48"
                cy="48"
                r="40"
                stroke="#18181b"
                strokeWidth="7"
                fill="transparent"
              />
              <circle
                cx="48"
                cy="48"
                r="40"
                stroke="#6366f1"
                strokeWidth="8"
                strokeDasharray="251.2"
                strokeDashoffset={251.2 - (251.2 * evaluation.overallScore) / 100}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-1000 ease-out"
              />
            </svg>
            <div className="absolute text-center">
              <span className="text-2xl font-black font-mono text-white">{evaluation.overallScore}</span>
              <span className="text-zinc-500 text-[10px] font-bold block">%</span>
            </div>
          </div>

          <div className="flex items-center gap-1 bg-emerald-950/20 text-emerald-400 border border-emerald-500/20 rounded px-2 py-0.5 text-[10px] font-mono font-semibold">
            <Trophy className="h-3 w-3 text-emerald-400" /> VERIFIED AGENT
          </div>

          {latencyMs && (
            <div className="text-[10px] text-zinc-500 mt-3 font-mono">
              Pipeline Latency: <span className="text-zinc-350">{(latencyMs / 1000).toFixed(2)}s</span>
            </div>
          )}
        </div>

        {/* Detailed Individual Metric Gauges */}
        <div className="md:col-span-3 space-y-4">
          {scores.map(metric => (
            <div key={metric.label} className={`p-4 rounded-lg border border-zinc-800 transition-all ${metric.bgColor}`}>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-mono font-semibold text-zinc-205">{metric.label}</span>
                <span className={`text-sm font-bold font-mono ${getScoreColor(metric.value)}`}>
                  {metric.value}%
                </span>
              </div>
              
              {/* Progress bar */}
              <div className="w-full bg-zinc-950 h-2 rounded overflow-hidden mb-2 border border-zinc-900">
                <div 
                  className={`bg-gradient-to-r ${metric.color} h-full rounded transition-all duration-1000`}
                  style={{ width: `${metric.value}%` }}
                />
              </div>

              <p className="text-[11px] text-zinc-400 font-sans tracking-wide leading-relaxed">
                {metric.desc}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Critic's detailed qualitative assessment feedback */}
      <div className="bg-zinc-950 border border-zinc-800 rounded-lg p-4 mt-6">
        <h4 className="text-xs font-mono font-semibold text-zinc-300 flex items-center gap-1.5 mb-2.5">
          <Info className="h-4.5 w-4.5 text-indigo-400" />
          CRITIC QUALITATIVE FEEDBACK AUDIT TRAILS
        </h4>
        <p className="text-xs text-zinc-300 font-mono leading-relaxed bg-[#0B0B0E] p-3 rounded border border-zinc-900/60">
          {evaluation.detailedFeedback}
        </p>
      </div>
    </div>
  );
};
