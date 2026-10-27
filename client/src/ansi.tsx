// Minimal ANSI SGR renderer for task output (colors/bold only; other escapes stripped).
const FG: Record<string, string> = {
  '30': '#6e7681', '31': '#f47067', '32': '#4ec9b0', '33': '#daaa3f', '34': '#6cb6ff', '35': '#b072e8', '36': '#56d4dd', '37': '#d4d4d4',
  '90': '#8b949e', '91': '#ff7b72', '92': '#7ee787', '93': '#e3b341', '94': '#79c0ff', '95': '#d2a8ff', '96': '#a5d6ff', '97': '#ffffff',
};
const BG: Record<string, string> = { '40': '', '41': '#5a1d1d', '42': '#0d3d33', '43': '#4d3800', '44': '#0c2d6b', '45': '#3c2a4e', '46': '#0b3e4a', '47': '#30363d' };

interface Seg { text: string; color?: string; bg?: string; bold?: boolean }

export function ansiSegments(line: string): Seg[] {
  const out: Seg[] = [];
  let color: string | undefined, bg: string | undefined, bold = false, pos = 0;
  const push = (end: number) => {
    if (end > pos) out.push({ text: line.slice(pos, end), color, bg, bold });
  };
  const re = /\x1b\[([0-9;]*)m/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) {
    push(m.index);
    pos = m.index + m[0].length;
    const codes = (m[1] || '0').split(';').map(Number);
    for (const c of codes) {
      if (c === 0) { color = undefined; bg = undefined; bold = false; }
      else if (c === 1) bold = true;
      else if (FG[String(c)]) color = FG[String(c)];
      else if (BG[String(c)]) bg = BG[String(c)];
    }
  }
  push(line.length);
  return out.map((s) => ({ ...s, text: s.text.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '') })).filter((s) => s.text);
}

export function Ansi({ line }: { line: string }) {
  if (!line.includes('\x1b[')) return <>{line}</>;
  const segs = ansiSegments(line);
  return <>{segs.map((s, i) => (
    <span key={i} style={{ color: s.color, background: s.bg || undefined, fontWeight: s.bold ? 700 : undefined }}>{s.text}</span>
  ))}</>;
}
