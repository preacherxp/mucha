// Prints web/bloom.svg: a pinwheel of whiplash petals centred on 0,0, used as a CSS mask.
const N = 9, VALLEY = 300, TIP = 495, step = (Math.PI * 2) / N;
const pt = (r, a) => [r * Math.cos(a), r * Math.sin(a)];
const f = (p) => `${p[0].toFixed(1)} ${p[1].toFixed(1)}`;

let silhouette = `M${f(pt(VALLEY, 0))}`;
for (let i = 0; i < N; i++) {
  const a0 = i * step, a1 = (i + 1) * step;
  const tipAngle = a0 + step * 0.78; // leans forward, so the ring reads as turning
  const tip = pt(TIP, tipAngle);
  // Long leading edge: swells out, then whips round into the tip.
  silhouette += `C${f(pt(VALLEY + 45, a0 + step * 0.04))} ${f(pt(TIP - 30, a0 + step * 0.34))} ${f(tip)}`;
  // Short trailing edge: a hollow curve falling back to the next valley.
  silhouette += `C${f(pt(TIP - 95, tipAngle + step * 0.02))} ${f(pt(VALLEY + 22, a1 - step * 0.2))} ${f(pt(VALLEY, a1))}`;
}
silhouette += 'Z';

process.stdout.write(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="-500 -500 1000 1000">
  <path d="${silhouette}"/>
</svg>
`);
