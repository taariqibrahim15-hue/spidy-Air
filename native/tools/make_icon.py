"""
Generate spider.ico for the native app from a vector-style drawing.

Run:  python native/tools/make_icon.py
Output: native/src/spider.ico  (16,32,48,64,128,256 px)
"""
from __future__ import annotations

import math
import os

from PIL import Image, ImageDraw

TEAL = (45, 212, 191, 255)
TEAL_DK = (15, 118, 110, 255)
TEAL_LT = (94, 234, 212, 255)
DARK = (2, 44, 34, 255)
BG = (6, 11, 18, 0)  # transparent


def draw_spider(size: int) -> Image.Image:
    # Supersample for smooth curves
    s = size * 4
    img = Image.new("RGBA", (s, s), BG)
    d = ImageDraw.Draw(img)
    cx, cy = s / 2, s / 2
    lw = max(2, int(s * 0.03))

    # subtle web strands
    for ang in range(0, 360, 45):
        a = math.radians(ang)
        d.line([(cx, cy), (cx + math.cos(a) * s * 0.46,
                            cy + math.sin(a) * s * 0.46)],
               fill=(45, 212, 191, 70), width=max(1, lw // 3))

    # legs (4 each side), as poly-lines with bend
    body_y = cy + s * 0.10
    leg_specs = [
        (-1, 0.08, 0.40, -0.10),
        (-1, 0.14, 0.44, 0.02),
        (-1, 0.22, 0.42, 0.16),
        (-1, 0.30, 0.34, 0.30),
        (1, 0.08, 0.40, -0.10),
        (1, 0.14, 0.44, 0.02),
        (1, 0.22, 0.42, 0.16),
        (1, 0.30, 0.34, 0.30),
    ]
    for side, oy, reach, dy in leg_specs:
        x0 = cx + side * s * 0.10
        y0 = body_y + (oy - 0.14) * s
        bx = cx + side * s * (0.10 + reach * 0.55)
        by = y0 + dy * s * 0.4 - s * 0.05
        ex = cx + side * s * (0.10 + reach)
        ey = y0 + dy * s
        d.line([(x0, y0), (bx, by), (ex, ey)], fill=TEAL_DK,
               width=lw, joint="curve")

    # abdomen
    rax, ray = s * 0.165, s * 0.20
    d.ellipse([cx - rax, body_y - ray, cx + rax, body_y + ray],
              fill=TEAL)
    # head
    hr = s * 0.11
    hy = cy - s * 0.08
    d.ellipse([cx - hr, hy - hr, cx + hr, hy + hr], fill=TEAL_LT)

    # hourglass marking
    hw = s * 0.05
    d.polygon([(cx - hw, body_y - ray * 0.4), (cx + hw, body_y - ray * 0.4),
               (cx, body_y + ray * 0.45)], fill=DARK)

    # eyes
    er = max(1, s * 0.012)
    d.ellipse([cx - s * 0.045 - er, hy - er, cx - s * 0.045 + er, hy + er],
              fill=DARK)
    d.ellipse([cx + s * 0.045 - er, hy - er, cx + s * 0.045 + er, hy + er],
              fill=DARK)

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "..", "src", "spider.ico")
    sizes = [16, 32, 48, 64, 128, 256]
    base = draw_spider(256)
    imgs = [draw_spider(n) for n in sizes]
    base.save(out, format="ICO",
              sizes=[(n, n) for n in sizes],
              append_images=imgs)
    print("wrote", os.path.normpath(out))


if __name__ == "__main__":
    main()
