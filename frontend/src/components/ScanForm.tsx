import React, { useState } from "react";

type ScanFormProps = {
  onSubmit: (domain: string) => void;
  onBulk: (domains: string[]) => void;
  loading: boolean;
};

export const ScanForm: React.FC<ScanFormProps> = ({ onSubmit, onBulk, loading }) => {
  const [mode, setMode] = useState<"single" | "bulk">("single");
  const [domain, setDomain] = useState("");
  const [bulkText, setBulkText] = useState("");

  const submitSingle = (e: React.FormEvent) => {
    e.preventDefault();
    const t = domain.trim();
    if (t) onSubmit(t);
  };

  const submitBulk = () => {
    const domains = bulkText.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
    if (domains.length) onBulk(domains);
  };

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="inline-flex rounded-lg border border-slate-700 overflow-hidden text-xs">
        <button onClick={() => setMode("single")} disabled={loading}
          className={`px-3 py-1.5 ${mode === "single" ? "bg-sky-600 text-white" : "bg-slate-900 text-slate-400"}`}>Single</button>
        <button onClick={() => setMode("bulk")} disabled={loading}
          className={`px-3 py-1.5 ${mode === "bulk" ? "bg-sky-600 text-white" : "bg-slate-900 text-slate-400"}`}>Bulk</button>
      </div>

      {mode === "single" ? (
        <form onSubmit={submitSingle} className="flex justify-center w-full">
          <div className="flex w-full max-w-md gap-3">
            <input type="text" placeholder="Enter a domain (example.com)" value={domain}
              onChange={(e) => setDomain(e.target.value)} disabled={loading}
              className="flex-1 rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-sky-500" />
            <button type="submit" disabled={loading}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed">
              {loading ? "Scanning…" : "Start"}
            </button>
          </div>
        </form>
      ) : (
        <div className="flex w-full max-w-md flex-col gap-2">
          <textarea rows={4} placeholder={"One domain per line (max 50)\nexample.com\nevil.tld"} value={bulkText}
            onChange={(e) => setBulkText(e.target.value)} disabled={loading}
            className="rounded-lg bg-slate-900 border border-slate-700 px-3 py-2 text-sm font-mono text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-sky-500" />
          <button onClick={submitBulk} disabled={loading}
            className="px-4 py-2 rounded-lg text-sm font-medium bg-sky-600 hover:bg-sky-500 disabled:opacity-50">
            {loading ? "Scanning…" : "Scan all"}
          </button>
        </div>
      )}
    </div>
  );
};
