#!/usr/bin/env python3
"""Generate Qira Notify PWA icons.

Produces four PNGs under landing/notify/:
  - icon-192.png   (Android home-screen, notification badge base)
  - icon-512.png   (PWA splash/installer)
  - icon-maskable-192.png  (Android adaptive icon — safe zone: inner 80%)
  - icon-maskable-512.png

Design language:
  - Dark purple background (#0d0b15) — matches site bg
  - Violet accent ring (#7b61ff) — matches accent CSS var
  - Centered lock glyph rendered from primitives (no font dep)

Run manually when the brand palette changes — these are static assets.
"""

from PIL import Image, ImageDraw
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
BG = (13, 11, 21, 255)          # #0d0b15
ACCENT = (123, 97, 255, 255)    # #7b61ff
RING_INNER = (24, 20, 39, 255)  # between bg and accent
LOCK_COLOR = (236, 235, 240, 255)  # #ecebf0
# Maskable safe zone: center 80% — everything outside can be cropped
# by the launcher when producing an adaptive icon.
MASKABLE_PAD_RATIO = 0.14  # ~86% of the way in

def round_rect(draw, box, radius, fill):
    x0, y0, x1, y1 = box
    draw.rounded_rectangle(box, radius=radius, fill=fill)

def draw_icon(size, maskable=False):
    img = Image.new("RGBA", (size, size), BG if not maskable else BG)
    d = ImageDraw.Draw(img)

    # The draw area shrinks when the icon is maskable so the launcher
    # has room to clip without cutting off the glyph.
    pad = int(size * MASKABLE_PAD_RATIO) if maskable else 0

    # Outer accent ring (thick circle)
    ring_thick = max(4, size // 24)
    ring_box = (pad + ring_thick, pad + ring_thick,
                size - pad - ring_thick, size - pad - ring_thick)
    d.ellipse(ring_box, outline=ACCENT, width=ring_thick)

    # Inner dark plate to sit the lock on
    inset = int((size - 2 * pad) * 0.14) + ring_thick
    plate_box = (pad + inset, pad + inset, size - pad - inset, size - pad - inset)
    d.ellipse(plate_box, fill=RING_INNER)

    # Lock body (rounded rectangle)
    body_w = int((size - 2 * pad) * 0.44)
    body_h = int((size - 2 * pad) * 0.28)
    cx, cy = size // 2, int(size * 0.58)
    body_box = (cx - body_w // 2, cy - body_h // 2,
                cx + body_w // 2, cy + body_h // 2)
    round_rect(d, body_box, radius=max(6, size // 24), fill=LOCK_COLOR)

    # Keyhole on the body
    hole_r = max(3, size // 42)
    hole_cx, hole_cy = cx, cy - body_h // 8
    d.ellipse((hole_cx - hole_r, hole_cy - hole_r,
               hole_cx + hole_r, hole_cy + hole_r), fill=BG)
    # Small tail on keyhole
    d.rectangle((hole_cx - hole_r // 2, hole_cy,
                 hole_cx + hole_r // 2, hole_cy + int(hole_r * 2.2)),
                fill=BG)

    # Shackle (arch above the body)
    shackle_thick = max(5, size // 22)
    shackle_w = int(body_w * 0.72)
    shackle_top = cy - body_h // 2 - int(body_h * 1.3)
    shackle_box = (cx - shackle_w // 2, shackle_top,
                   cx + shackle_w // 2, cy - body_h // 2 + shackle_thick // 2)
    # Draw arc: 180° sweep over the top half of the shackle box.
    d.arc(shackle_box, start=180, end=360, fill=LOCK_COLOR, width=shackle_thick)

    return img

for s in (192, 512):
    icon = draw_icon(s, maskable=False)
    icon.save(os.path.join(OUT_DIR, f"icon-{s}.png"), "PNG")
    mask = draw_icon(s, maskable=True)
    mask.save(os.path.join(OUT_DIR, f"icon-maskable-{s}.png"), "PNG")
    print(f"wrote icon-{s}.png + icon-maskable-{s}.png")
