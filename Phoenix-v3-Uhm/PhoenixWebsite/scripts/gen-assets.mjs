import zlib from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crc]);
}

function encodePNG(width, height, draw) {
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) {
    const rowStart = y * (width * 4 + 1);
    raw[rowStart] = 0;
    for (let x = 0; x < width; x++) {
      const [r, g, b, a] = draw(x, y);
      const i = rowStart + 1 + x * 4;
      raw[i] = r;
      raw[i + 1] = g;
      raw[i + 2] = b;
      raw[i + 3] = a;
    }
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([
    sig,
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function save(rel, buf) {
  const p = resolve(process.cwd(), "public", rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, buf);
  console.log("wrote", rel, buf.length, "bytes");
}

function logoPixel(size) {
  const c = size / 2;
  return (x, y) => {
    const dx = x - c;
    const dy = y - c;
    const dist = Math.hypot(dx, dy);
    if (dist > c - 1) return [0, 0, 0, 0];
    const ang = Math.atan2(dy, dx);

    const spoke = Math.abs(Math.sin(ang * 3)) > 0.86 && dist > c * 0.18;
    const core = dist < c * 0.22;
    const t = dist / c;

    const r = Math.round(255 + (226 - 255) * t);
    const g = Math.round(184 + (90 - 184) * t);
    const b = Math.round(119 + (0 - 119) * t);
    if (spoke || core) return [255, 243, 230, 255];
    return [r, g, b, Math.round(85 * (1 - t))];
  };
}

const SIZE = 256;
save("logo.png", encodePNG(SIZE, SIZE, logoPixel(SIZE)));
save("favicon.ico", encodePNG(64, 64, logoPixel(64)));

save(
  "mainpage.png",
  encodePNG(1200, 800, (x, y) => {
    const cx = 600;
    const cy = 400;
    const d = Math.hypot((x - cx) / 600, (y - cy) / 400);
    const a = Math.max(0, 1 - d);
    return [29, 78, 216, Math.round(120 * a)];
  })
);

const partners = ["enveart", "impero", "vanquest"];
for (const name of partners) {
  save(
    `partners/${name}.png`,
    encodePNG(200, 200, (x, y) => {
      const inset = x > 30 && x < 170 && y > 70 && y < 130;
      return inset ? [255, 255, 255, 235] : [0, 0, 0, 0];
    })
  );
}
