// Prints web/bloom.svg: a pinwheel of whiplash petals centred on 0,0, plus the gold line work.
// #petals is the only thing painted, so the file works directly as a CSS mask. The lines live in <defs>.
const N = 9, VALLEY = 300, TIP = 495, TAU = Math.PI * 2, step = TAU / N;
const pt = (r, a) => [r * Math.cos(a), r * Math.sin(a)];
const f = (p) => `${p[0].toFixed(1)} ${p[1].toFixed(1)}`;

let silhouette = `M${f(pt(VALLEY, 0))}`;
const lines = [];
for (let i = 0; i < N; i++) {
  const a0 = i * step, a1 = (i + 1) * step;
  const tipAngle = a0 + step * 0.78; // leans forward, so the ring reads as turning
  const tip = pt(TIP, tipAngle);
  // Long leading edge: swells out, then whips round into the tip.
  silhouette += `C${f(pt(VALLEY + 45, a0 + step * 0.04))} ${f(pt(TIP - 30, a0 + step * 0.34))} ${f(tip)}`;
  // Short trailing edge: a hollow curve falling back to the next valley.
  silhouette += `C${f(pt(TIP - 95, tipAngle + step * 0.02))} ${f(pt(VALLEY + 22, a1 - step * 0.2))} ${f(pt(VALLEY, a1))}`;

  // The vein: an S-curve from the petal's body down toward the centre.
  const start = pt(TIP - 48, a0 + step * 0.62);
  const end = pt(150, a0 - step * 0.55);
  lines.push(`M${f(start)}C${f(pt(TIP - 150, a0 + step * 0.34))} ${f(pt(330, a0 + step * 0.32))} ${f(pt(255, a0 + step * 0.02))}S${f(pt(190, a0 - step * 0.28))} ${f(end)}`);

  // The curl at the end of the vein: a small spiral, the classic whiplash terminal.
  // It starts tangent to the vein's final direction, so the two read as one unbroken stroke.
  const control = pt(190, a0 - step * 0.28), R = 15;
  const len = Math.hypot(end[0] - control[0], end[1] - control[1]);
  const d = [(end[0] - control[0]) / len, (end[1] - control[1]) / len];
  const centre = [end[0] - d[1] * R, end[1] + d[0] * R];
  const start0 = Math.atan2(end[1] - centre[1], end[0] - centre[0]);
  let curl = `M${f(end)}`;
  for (let t = 1; t <= 48; t++) {
    const p = t / 48, r = R * (1 - 0.82 * p), a = start0 + p * TAU * 1.4;
    curl += `L${(centre[0] + r * Math.cos(a)).toFixed(2)} ${(centre[1] + r * Math.sin(a)).toFixed(2)}`;
  }
  lines.push(curl);
}
silhouette += 'Z';

const out = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="-500 -500 1000 1000">
  <path id="petals" d="${silhouette}"/>
  <defs>
    <g id="lines" fill="none" stroke-linecap="round" stroke-linejoin="round">
      <path vector-effect="non-scaling-stroke" stroke-width="1.6" d="${silhouette}"/>
      <path vector-effect="non-scaling-stroke" stroke-width="1" d="${lines.join('')}"/>
    </g>
  </defs>
</svg>
`;
process.stdout.write(out);
