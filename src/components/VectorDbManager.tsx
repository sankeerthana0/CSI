import React, { useState } from 'react';
import { KnowledgeDocument } from '../types';
import { Database, Plus, Search, Tag, Eye, Info, RefreshCw, AlertCircle, CheckCircle } from 'lucide-react';

interface VectorDbManagerProps {
  documents: KnowledgeDocument[];
  onAddDocument: (doc: { title: string; text: string; source: string; tags: string[] }) => Promise<void>;
  isLoading: boolean;
}

export const VectorDbManager: React.FC<VectorDbManagerProps> = ({ documents, onAddDocument, isLoading }) => {
  const [search, setSearch] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newText, setNewText] = useState('');
  const [newSource, setNewSource] = useState('');
  const [newTagsStr, setNewTagsStr] = useState('');
  const [addStatus, setAddStatus] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle || !newText) {
      setAddStatus({ type: 'error', message: 'Title and content text are required.' });
      return;
    }

    try {
      const tags = newTagsStr.split(',').map(t => t.trim()).filter(Boolean);
      await onAddDocument({
        title: newTitle,
        text: newText,
        source: newSource || 'Manual Operator Upload',
        tags
      });
      setAddStatus({ type: 'success', message: 'Document split & indexed successfully into Vector Database!' });
      setNewTitle('');
      setNewText('');
      setNewSource('');
      setNewTagsStr('');
      setTimeout(() => setAddStatus(null), 4000);
    } catch (e: any) {
      setAddStatus({ type: 'error', message: e.message || 'Failed to index document.' });
    }
  };

  const filteredDocs = documents.filter(doc => 
    doc.title.toLowerCase().includes(search.toLowerCase()) ||
    doc.text.toLowerCase().includes(search.toLowerCase()) ||
    doc.tags.some(t => t.toLowerCase().includes(search.toLowerCase()))
  );

  return (
    <div className="bg-[#0E0E11] border border-zinc-800 rounded-xl p-6 shadow-2xl relative">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-4 mb-6">
        <div>
          <h3 className="text-md font-mono font-semibold text-white flex items-center gap-2">
            <Database className="h-4.5 w-4.5 text-indigo-400" />
            CHROMADB & FAISS KNOWLEDGE CORE (RAG INDEX)
          </h3>
          <p className="text-xs text-zinc-400 mt-1">
            Browse and expand verified campaign indicators, APT methodologies, and vulnerability rules.
          </p>
        </div>

        <button
          onClick={() => setShowAddForm(!showAddForm)}
          className="flex items-center gap-1.5 text-xs font-mono bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 px-3 py-2 rounded-md border border-indigo-500/20 transition-all cursor-pointer self-start sm:self-auto"
        >
          <Plus className="h-3.5 w-3.5" />
          {showAddForm ? 'COLLAPSE UPLOADER' : 'INDEX INTEL RECORD'}
        </button>
      </div>

      {/* Index Form Drawer */}
      {showAddForm && (
        <form onSubmit={handleSubmit} className="bg-zinc-900/10 border border-zinc-800 rounded-lg p-4 mb-6 relative">
          <h4 className="text-xs font-mono font-bold text-indigo-400 mb-4 flex items-center gap-1">
            <Info className="h-3.5 w-3.5" /> INDEX TARGET INTEL PACKETS
          </h4>

          {addStatus && (
            <div className={`p-2.5 rounded text-xs font-mono mb-4 flex items-center gap-2 ${
              addStatus.type === 'success' ? 'bg-emerald-950/20 text-emerald-400 border border-emerald-500/20' : 'bg-red-950/20 text-red-500 border border-red-500/20'
            }`}>
              {addStatus.type === 'success' ? <CheckCircle className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
              {addStatus.message}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">INTEL REPORT TITLE *</label>
              <input
                type="text"
                placeholder="e.g. Volt Typhoon Lateral Port Forwarding Rules"
                value={newTitle}
                onChange={e => setNewTitle(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-850 focus:border-indigo-500 focus:outline-none rounded px-3 py-2 text-xs text-zinc-200"
                required
              />
            </div>
            <div>
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">REPORT SOURCE / METADATA</label>
              <input
                type="text"
                placeholder="e.g. Mandiant APT Report, CVE Bulletin"
                value={newSource}
                onChange={e => setNewSource(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-850 focus:border-indigo-500 focus:outline-none rounded px-3 py-2 text-xs text-zinc-200"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">METADATA KEYWORD TAGS (COMMA SEPARATED)</label>
              <input
                type="text"
                placeholder="APT29, Cozy Bear, 193.23.45.166, T1090"
                value={newTagsStr}
                onChange={e => setNewTagsStr(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-850 focus:border-indigo-500 focus:outline-none rounded px-3 py-2 text-xs text-zinc-200"
              />
            </div>
            <div className="md:col-span-2">
              <label className="block text-[11px] font-mono text-zinc-400 mb-1">INTEL BODY TEXT / METHODOLOGY CONTENT *</label>
              <textarea
                placeholder="Paste raw intel briefs, TTPs, or technical IOC documentation here..."
                rows={4}
                value={newText}
                onChange={e => setNewText(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-850 focus:border-indigo-500 focus:outline-none rounded px-3 py-2 text-xs text-zinc-200 font-mono"
                required
              />
            </div>
          </div>

          <div className="mt-4 flex justify-end">
            <button
              type="submit"
              disabled={isLoading}
              className="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded text-xs font-mono transition-all font-semibold cursor-pointer disabled:opacity-40"
            >
              {isLoading ? 'SPLITTING CHUNKS...' : 'INDEX DOCUMENT'}
            </button>
          </div>
        </form>
      )}

      {/* Filter and stats banner */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mb-4">
        {/* Search Input */}
        <div className="relative w-full sm:max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500" />
          <input
            type="text"
            placeholder="Search vector database..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-zinc-950 border border-zinc-850 rounded pl-9 pr-4 py-2 text-xs text-zinc-350 focus:border-indigo-500 focus:outline-none"
          />
        </div>

        <div className="text-[11px] font-mono text-zinc-400 self-end sm:self-auto">
          Displaying <span className="text-indigo-400 font-bold">{filteredDocs.length}</span> of <span className="text-zinc-300">{documents.length}</span> indexed vectors
        </div>
      </div>

      {/* Documents List */}
      <div className="space-y-4 max-h-[360px] overflow-y-auto pr-1">
        {filteredDocs.map(doc => (
          <div key={doc.id} className="bg-zinc-950/70 border border-zinc-800 hover:border-zinc-700 rounded-lg p-4 transition-all">
            <div className="flex items-start justify-between gap-2">
              <div className="flex-1">
                <div className="flex flex-wrap items-center gap-2 mb-1.5">
                  <span className="text-[10px] font-mono text-xs bg-indigo-500/10 text-indigo-300 px-2 py-0.5 rounded border border-indigo-500/20 font-bold">
                    {doc.id}
                  </span>
                  <span className="text-[10px] font-mono text-zinc-400">
                    Source: {doc.source}
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-white">{doc.title}</h4>
              </div>
            </div>

            <p className="text-xs text-zinc-400 mt-2 font-mono leading-relaxed bg-zinc-950 p-2.5 rounded border border-zinc-900/80">
              {doc.text}
            </p>

            <div className="flex flex-wrap gap-1.5 mt-3">
              {doc.tags.map(tag => (
                <div key={tag} className="flex items-center gap-1 text-[10px] font-mono bg-zinc-900 border border-zinc-800/80 text-zinc-300 px-2 py-0.5 rounded">
                  <Tag className="h-2.5 w-2.5 text-indigo-400" />
                  {tag}
                </div>
              ))}
            </div>
          </div>
        ))}

        {filteredDocs.length === 0 && (
          <div className="text-center py-8 border border-dashed border-zinc-800 rounded-lg">
            <AlertCircle className="h-8 w-8 text-zinc-650 mx-auto mb-2" />
            <h5 className="text-sm font-semibold text-zinc-450 font-mono">No matching indices found</h5>
            <p className="text-xs text-zinc-550 mt-1">Try searching for other tags like LockBit, Cozy Bear, Spring Boot or Tor.</p>
          </div>
        )}
      </div>
    </div>
  );
};
