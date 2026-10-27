// Generate Mobius Guard's logo files into .github/assets/.
//
// Usage:  npx -y -p playwright@1.58.2 node scripts/brand/generate.mjs
//         (then `npx playwright install chromium` once, if asked)
//
// Mobius Guard is a Gantrly project and follows Gantrly's brand (docs/brand.md in
// gantrly/gantrly): the amber tile with radius 14/64 and the mark at 70%, graphite ink,
// a lowercase Geist 700 wordmark at -4% tracking, and the Hi-vis palette. Only the mark
// is its own: a Mobius loop, one band with a twist, drawn over and under itself.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'

const here = path.dirname(fileURLToPath(import.meta.url))
const out = path.resolve(here, '../../.github/assets')
fs.mkdirSync(out, { recursive: true })

export const COLORS = {
  graphite: '#1B1E23',
  slate: '#3A414B',
  paper: '#F7F8F9',
  amber: '#F5B301',
  nightText: '#E8EBEE',
}
const NAME = 'mobius guard'
const TAGLINE = 'An open-source firewall for LLM apps.'
const TILE = { radius: 14, scale: 0.7 }

// The mark on a 64x64 grid: an infinity loop (a lemniscate of Bernoulli), one band that
// crosses itself in the middle. Near the crossing, one strand is drawn again on top of a
// short cut in the tile's colour, so the band reads as passing over itself, the twist of a
// Mobius strip. Both strands come from the same curve, so they line up exactly.
const A = 29 // half-width of the loop
const STROKE = 8.5
const CUT = STROKE + 6 // the cut is wider than the band, and shorter than the strand on top

function point(t) {
  const d = 1 + Math.sin(t) ** 2
  return [32 + (A * Math.cos(t)) / d, 32 + (A * Math.sin(t) * Math.cos(t)) / d]
}

function curve(from, to, steps) {
  const pts = []
  for (let i = 0; i <= steps; i++) pts.push(point(from + ((to - from) * i) / steps))
  return pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)} ${y.toFixed(2)}`).join(' ')
}

const LOOP = `${curve(0, 2 * Math.PI, 240)} Z`
const OVER = curve(Math.PI / 2 - 0.5, Math.PI / 2 + 0.5, 40) // the strand on top, at the crossing
const CUT_PATH = curve(Math.PI / 2 - 0.28, Math.PI / 2 + 0.28, 24)

function markShapes(ink, ground) {
  return (
    `<path d="${LOOP}" fill="none" stroke="${ink}" stroke-width="${STROKE}" stroke-linejoin="round"/>` +
    `<path d="${CUT_PATH}" fill="none" stroke="${ground}" stroke-width="${CUT}" stroke-linecap="butt"/>` +
    `<path d="${OVER}" fill="none" stroke="${ink}" stroke-width="${STROKE}" stroke-linecap="butt"/>`
  )
}

export function markSvg({ ink = COLORS.graphite, ground = '#FFFFFF', size = 64 } = {}) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="${size}" height="${size}" role="img"><title>Mobius Guard</title>${markShapes(ink, ground)}</svg>`
}

export function tileSvg({ size = 64, tile = COLORS.amber, ink = COLORS.graphite } = {}) {
  const inset = (64 - 64 * TILE.scale) / 2
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="${size}" height="${size}" role="img"><title>Mobius Guard</title><rect width="64" height="64" rx="${TILE.radius}" fill="${tile}"/><g transform="translate(${inset} ${inset}) scale(${TILE.scale})">${markShapes(ink, tile)}</g></svg>`
}

const FONT_CSS = 'https://fonts.googleapis.com/css2?family=Geist:wght@400..800&display=swap'

async function main() {
  fs.writeFileSync(path.join(out, 'tile.svg'), tileSvg())
  fs.writeFileSync(path.join(out, 'mark.svg'), markSvg())
  const browser = await chromium.launch()
  const retina = await browser.newPage({ deviceScaleFactor: 2 })
  const exact = await browser.newPage({ deviceScaleFactor: 1 })
  const render = async (html, width, height, file, transparent, page = retina) => {
    await page.setViewportSize({ width, height })
    await page.setContent(
      `<!doctype html><html><head><link rel="stylesheet" href="${FONT_CSS}"><style>html,body{margin:0}</style></head><body>${html}</body></html>`,
      { waitUntil: 'networkidle' },
    )
    await page.evaluate(() => document.fonts.ready)
    fs.writeFileSync(file, await page.screenshot({ omitBackground: transparent, type: 'png' }))
    console.log('wrote', path.relative(process.cwd(), file))
  }
  const lockup = (text) => `
    <div style="display:flex;align-items:center;gap:22px;height:120px;padding:0 8px">
      ${tileSvg({ size: 96 })}
      <span style="font-family:Geist;font-weight:700;font-size:80px;letter-spacing:-0.04em;line-height:1;color:${text};white-space:nowrap">${NAME}</span>
    </div>`
  await render(lockup(COLORS.graphite), 640, 120, path.join(out, 'lockup.png'), true)
  await render(lockup(COLORS.nightText), 640, 120, path.join(out, 'lockup-dark.png'), true)
  await render(
    `<div style="width:1200px;height:630px;box-sizing:border-box;padding:88px 96px;background:${COLORS.paper};display:flex;flex-direction:column;justify-content:space-between;font-family:Geist">
      <div style="display:flex;align-items:center;gap:28px">
        ${tileSvg({ size: 132 })}
        <span style="font-weight:700;font-size:112px;letter-spacing:-0.04em;line-height:1;color:${COLORS.graphite};white-space:nowrap">${NAME}</span>
      </div>
      <div style="display:flex;flex-direction:column;gap:18px">
        <div style="font-size:48px;font-weight:600;color:${COLORS.graphite};line-height:1.15">${TAGLINE}</div>
        <div style="font-size:26px;color:${COLORS.slate}">Open source · Apache-2.0 · a Gantrly project</div>
      </div>
      <div style="height:14px;border-radius:7px;background:${COLORS.amber};width:360px"></div>
    </div>`,
    1200,
    630,
    path.join(out, 'social-preview.png'),
    false,
    exact,
  )
  await browser.close()
}

await main()
