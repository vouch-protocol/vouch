// Generate a 128x128 PNG icon: parchment background, burgundy shield, white V.
// Pure JS, no canvas dep; uses pngjs to write raw pixel data.
const fs = require('fs');
const path = require('path');
const { PNG } = require('pngjs');

const SIZE = 128;
const png = new PNG({ width: SIZE, height: SIZE });

// Palette (RGBA)
const BG       = [245, 237, 221, 255]; // parchment
const SHIELD   = [123,  27,  49, 255]; // burgundy
const INK      = [255, 255, 255, 255]; // white V

function setPixel(x, y, [r, g, b, a]) {
  if (x < 0 || y < 0 || x >= SIZE || y >= SIZE) return;
  const i = (y * SIZE + x) * 4;
  png.data[i + 0] = r;
  png.data[i + 1] = g;
  png.data[i + 2] = b;
  png.data[i + 3] = a;
}

// Fill background.
for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    setPixel(x, y, BG);
  }
}

// Helper: point-in-polygon (ray casting).
function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    const intersect = (yi > y) !== (yj > y) &&
                      x < ((xj - xi) * (y - yi)) / (yj - yi || 1e-9) + xi;
    if (intersect) inside = !inside;
  }
  return inside;
}

// Shield (top-wide, bottom-pointed).
const pad = 14;
const SHIELD_POLY = [
  [pad,         pad + 6],
  [SIZE - pad,  pad + 6],
  [SIZE - pad,  Math.floor(SIZE * 0.55)],
  [SIZE / 2,    SIZE - pad],
  [pad,         Math.floor(SIZE * 0.55)],
];

// Two arms of a V.
const V_LEFT = [
  [38, 38],
  [48, 38],
  [SIZE / 2 + 2, 92],
  [SIZE / 2 - 4, 92],
];
const V_RIGHT = [
  [90, 38],
  [80, 38],
  [SIZE / 2 - 2, 92],
  [SIZE / 2 + 4, 92],
];

// Rasterize polygons in z-order: shield first, then V on top.
for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    if (inPoly(x + 0.5, y + 0.5, SHIELD_POLY)) {
      setPixel(x, y, SHIELD);
    }
  }
}
for (let y = 0; y < SIZE; y++) {
  for (let x = 0; x < SIZE; x++) {
    if (
      inPoly(x + 0.5, y + 0.5, V_LEFT) ||
      inPoly(x + 0.5, y + 0.5, V_RIGHT)
    ) {
      setPixel(x, y, INK);
    }
  }
}

const out = path.join(__dirname, 'images', 'icon.png');
fs.mkdirSync(path.dirname(out), { recursive: true });
png.pack().pipe(fs.createWriteStream(out)).on('finish', () => {
  const size = fs.statSync(out).size;
  console.log(`wrote ${out} (${size} bytes)`);
});
