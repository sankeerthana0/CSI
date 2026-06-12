export interface ThreatLog {
  id: string;
  title: string;
  source: string;
  type: 'log_file' | 'intel_report' | 'syslog_stream';
  content: string;
  timestamp: string;
  parsedMetadata: {
    ips: string[];
    domains: string[];
    hashes: string[];
    techniques: string[]; // MITRE ATT&CK techniques
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  };
}

export interface KnowledgeDocument {
  id: string;
  title: string;
  text: string;
  source: string;
  tags: string[];
  relevanceScore?: number; // Calculated on retrieval
}

export type LangGraphNodeId = 'ingest' | 'retrieve' | 'analysis' | 'summarize' | 'alert' | 'evaluate' | 'complete' | 'idle';

export interface WorkflowStepLog {
  nodeId: LangGraphNodeId;
  label: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  timestamp: string;
  payload?: any;
}

export interface AnalysisAgentResult {
  threatVector: string;
  associatedActors: string[];
  severityScore: number; // 0 to 10
  targetSystems: string[];
  indicatorsOfCompromise: string[];
  methodologies: string[];
  mitigations: string[];
}

export interface SummarizeAgentResult {
  headline: string;
  executiveSummary: string;
  keyTakeaways: string[];
}

export interface AlertingAgentResult {
  alertTriggered: boolean;
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  suggestedAction: string;
  payloadTemplate: string; // JSON alert notification structure
}

export interface EvaluationResult {
  relevanceScore: number; // 1-100
  faithfulnessScore: number; // 1-100
  accuracyScore: number; // 1-100
  overallScore: number; // 1-100
  detailedFeedback: string;
  evaluatorModel: string;
}

export interface AgentWorkflowRun {
  id: string;
  inputQuery: string;
  logsAnalyzed: ThreatLog[];
  retrievedDocs: KnowledgeDocument[];
  stepLogs: WorkflowStepLog[];
  analysis?: AnalysisAgentResult;
  summary?: SummarizeAgentResult;
  alert?: AlertingAgentResult;
  evaluation?: EvaluationResult;
  createdAt: string;
  latencyMs: number;
}
