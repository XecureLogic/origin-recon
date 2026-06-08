import React from "react";
import type { ScanDetail } from "../App";

type Props = { scan: ScanDetail };

// Size a box to its text so content never overflows; truncate gracefully.
const fit = (text: string, maxChars: number, px: number) => {
  const t = text.length > maxChars ? `${text.slice(0, maxChars - 1)}…` : text;
  const w = Math.max(110, Math.round(t.length * px) + 26);
  return { t, w };
};
const avg = (n: number[]) => (n.length ? n.reduce((a, b) => a + b, 0) / n.length : 0);

const Line: React.FC<{ x1: number; y1: number; x2: number; y2: number }> = ({ x1, y1, x2, y2 }) => (
  <line x1={x1} y1={y1} x2={x2} y2={y2} stroke="#334155" strokeWidth={1} />
);

export const GraphView: React.FC<Props> = ({ scan }) => {
  const records = scan.records || [];
  const aRecords = records.filter(r => r.type === "A" || r.type === "AAAA");
  const nsRecords = records.filter(r => r.type === "NS");
  const mxRecords = records.filter(r => r.type === "MX");
  const ips = Array.from(new Set([
    ...(scan.ips || []).map(i => i.ip),
    ...(aRecords.map(r => r.ip || r.value).filter(Boolean) as string[]),
  ]));
  if (!records.length) return <p className="text-sm text-slate-500">No DNS records to visualize yet.</p>;

  const W = 1020;
  const apexLeft = 14, xType = 310, xHost = 590, xIp = 900, row = 58;

  const aY = aRecords.map((_, i) => 70 + i * row);
  const nsBase = 70 + Math.max(aRecords.length, 1) * row + 45;
  const nsY = nsRecords.map((_, i) => nsBase + i * row);
  const mxBase = nsBase + Math.max(nsRecords.length, 1) * row + 45;
  const mxY = mxRecords.map((_, i) => mxBase + i * row);
  const ipY = ips.map((_, i) => 70 + i * row);
  const ipMap = new Map<string, number>(); ips.forEach((ip, i) => ipMap.set(ip, ipY[i]));
  const ipBox = new Map<string, number>(); ips.forEach(ip => ipBox.set(ip, fit(ip, 20, 7).w));
  const domainY = avg([...aY, ...nsY, ...mxY, ...ipY]) || 120;
  const height = Math.max(mxY[mxY.length - 1] || 260, ipY[ipY.length - 1] || 260) + 85;

  const apex = fit(scan.domain, 37, 6.6);
  const apexRight = apexLeft + apex.w;

  const hostNode = (name: string, x: number, y: number, stroke: string, maxChars: number) => {
    const f = fit(name, maxChars, 6.2);
    return (
      <g>
        <rect x={x - f.w / 2} y={y - 18} width={f.w} height={36} rx={8} fill="#111827" stroke={stroke} />
        <text x={x} y={y + 4} textAnchor="middle" className="text-[11px]" fill="#e5e7eb">{f.t}</text>
      </g>
    );
  };

  return (
    <div className="border border-slate-800 rounded-2xl bg-slate-950 p-3 overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${height}`} className="w-full min-w-[760px]" aria-label="DNS graph">
        {/* apex */}
        <rect x={apexLeft} y={domainY - 22} width={apex.w} height={44} rx={8} fill="#0b1120" stroke="#eab308" strokeWidth={1.2} />
        <text x={apexLeft + apex.w / 2} y={domainY + 4} textAnchor="middle" fill="#e5e7eb" className="text-[12px]">
          <title>{scan.domain}</title>{apex.t}
        </text>

        {/* A / AAAA */}
        {aRecords.length > 0 && (
          <>
            <circle cx={xType} cy={avg(aY)} r={16} fill="#1f2933" stroke="#4d7c50" strokeWidth={1.4} />
            <text x={xType} y={avg(aY) + 4} textAnchor="middle" className="text-xs" fill="#e5e7eb">A</text>
            <Line x1={apexRight} y1={domainY} x2={xType - 16} y2={avg(aY)} />
            {aRecords.map((r, i) => {
              const ip = (r.ip || r.value) as string;
              const y = aY[i];
              const it = ipMap.get(ip);
              const f = fit(r.name, 46, 6.2);
              return (
                <g key={`a-${i}`}>
                  <Line x1={xType + 16} y1={avg(aY)} x2={xHost - f.w / 2} y2={y} />
                  {it !== undefined && <Line x1={xHost + f.w / 2} y1={y} x2={xIp - (ipBox.get(ip)! / 2)} y2={it} />}
                  {hostNode(r.name, xHost, y, "#4d7c50", 46)}
                </g>
              );
            })}
          </>
        )}

        {/* NS */}
        {nsRecords.length > 0 && (
          <>
            <circle cx={xType} cy={avg(nsY)} r={16} fill="#1f2933" stroke="#64748b" strokeWidth={1.4} />
            <text x={xType} y={avg(nsY) + 4} textAnchor="middle" className="text-xs" fill="#e5e7eb">DNS</text>
            <Line x1={apexRight} y1={domainY} x2={xType - 16} y2={avg(nsY)} />
            {nsRecords.map((r, i) => {
              const f = fit(r.name, 46, 6.2);
              return (
                <g key={`ns-${i}`}>
                  <Line x1={xType + 16} y1={avg(nsY)} x2={xHost - f.w / 2} y2={nsY[i]} />
                  {hostNode(r.name, xHost, nsY[i], "#64748b", 46)}
                </g>
              );
            })}
          </>
        )}

        {/* MX */}
        {mxRecords.length > 0 && (
          <>
            <circle cx={xType} cy={avg(mxY)} r={16} fill="#1f2933" stroke="#3b6fb3" strokeWidth={1.4} />
            <text x={xType} y={avg(mxY) + 4} textAnchor="middle" className="text-xs" fill="#e5e7eb">MX</text>
            <Line x1={apexRight} y1={domainY} x2={xType - 16} y2={avg(mxY)} />
            {mxRecords.map((r, i) => {
              const f = fit(r.name, 52, 6.2);
              return (
                <g key={`mx-${i}`}>
                  <Line x1={xType + 16} y1={avg(mxY)} x2={xHost - f.w / 2} y2={mxY[i]} />
                  {hostNode(r.name, xHost, mxY[i], "#3b6fb3", 52)}
                </g>
              );
            })}
          </>
        )}

        {/* IPs */}
        {ips.map((ip, i) => {
          const w = ipBox.get(ip)!;
          return (
            <g key={ip}>
              <rect x={xIp - w / 2} y={ipY[i] - 22} width={w} height={44} rx={8} fill="#111827" stroke="#b59f3b" />
              <text x={xIp} y={ipY[i] - 2} textAnchor="middle" className="text-[11px]" fill="#facc15">{ip}</text>
              <text x={xIp} y={ipY[i] + 12} textAnchor="middle" className="text-[9px]" fill="#9ca3af">network</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};
