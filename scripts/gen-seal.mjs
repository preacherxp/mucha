// Prints a seal whose scalloped edge is computed around the centre, so it cannot drift off it.
const C = 32, OUTER = 31, INNER = 27.5, TEETH = 16;
const pts = [];
for (let i = 0; i < TEETH * 2; i++) {
  const r = i % 2 ? INNER : OUTER, a = (i * Math.PI) / TEETH - Math.PI / 2;
  pts.push(`${(C + r * Math.cos(a)).toFixed(2)} ${(C + r * Math.sin(a)).toFixed(2)}`);
}
console.log(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <path fill="#93321f" d="M${pts.join('L')}Z"/>
  <circle cx="32" cy="32" r="22.5" fill="none" stroke="#e7b9a6" stroke-width="1.5"/>
  <path d="M23 41V23l9 11.5L41 23v18" fill="none" stroke="#f3d6c4" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"/>
</svg>`);
