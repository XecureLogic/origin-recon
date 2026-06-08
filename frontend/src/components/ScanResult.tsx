import React from "react";
import type { ScanDetail } from "../App";
import { GraphView } from "./GraphView";
import { SystemLocations } from "./SystemLocations";
import { RecordsTable } from "./RecordsTable";
import { Verdict } from "./Verdict";

type ScanResultProps = {
  scan: ScanDetail;
  onExportIocs: () => void;
  onExportFeed: (kind: "stix" | "misp") => void;
};

export const ScanResult: React.FC<ScanResultProps> = ({ scan, onExportIocs, onExportFeed }) => {
  return (
    <section className="space-y-6">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:p-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Scan summary</h2>
            <p className="text-xs text-slate-400 mt-1">
              Results for <span className="font-mono text-slate-100">{scan.domain}</span>
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-xs">
            <div><div className="text-slate-400">Status</div><div className="font-medium text-emerald-400">{scan.status}</div></div>
            <div><div className="text-slate-400">Hosts</div><div className="font-mono text-slate-200">{scan.ips?.length ?? 0}</div></div>
            <div><div className="text-slate-400">Subdomains</div><div className="font-mono text-slate-200">{scan.subdomains?.length ?? 0}</div></div>
            <button
              onClick={onExportIocs}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700"
            >
              IOCs (CSV)
            </button>
            <button
              onClick={() => onExportFeed("stix")}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700"
              title="STIX 2.1 bundle"
            >
              STIX
            </button>
            <button
              onClick={() => onExportFeed("misp")}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 border border-slate-700"
              title="MISP event JSON"
            >
              MISP
            </button>
          </div>
        </div>
      </div>

      <Verdict scan={scan} />

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:p-5">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-slate-200">DNS Graph</h3>
          <p className="text-[11px] text-slate-500">XecureLogic · Origin Recon</p>
        </div>
        <GraphView scan={scan} />
      </div>

      <SystemLocations scan={scan} />

      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-4 md:p-5">
        <h3 className="text-sm font-semibold text-slate-200 mb-3">DNS Records</h3>
        <RecordsTable scan={scan} />
      </div>
    </section>
  );
};
