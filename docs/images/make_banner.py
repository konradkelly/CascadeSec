"""Draw the CascadeSec banner as pixel art: one grid, two outputs.

    python docs/images/make_banner.py docs/images

writes cascadesec-banner.svg (the README's header; crisp at any width) and
cascadesec-banner.png (1280x640, GitHub's social-preview size). Standard
library only, so it runs anywhere the repo does. Edit the grid below and
run it again; the images are committed, so the README never depends on it.

The picture: a terminal running `cascadesec scan .`, the wordmark shaded
cyan to green, and under it a cascade -- steps that each land on the one
before, ending in a check. That is the product's own shape: fixes chained
one on another, each verified before the next.
"""

import struct
import sys
import zlib
from pathlib import Path

W, H = 160, 80   # grid cells
SCALE = 8        # PNG pixels per cell -> 1280 x 640

BG = "#0b1020"
FRAME = "#2a3550"
TITLE_BAR = "#1a2238"
BODY = "#0f1626"
TEXT = "#e5e7eb"
DIM = "#94a3b8"
PROMPT = "#4ade80"
CYAN = "#22d3ee"
GREEN = "#4ade80"
SHADOW = "#134e5e"
DOTS = ("#ff5f57", "#febc2e", "#28c840")

# 5x7 glyphs, rows top to bottom.
FONT = {
    "A": "01110 10001 10001 11111 10001 10001 10001",
    "C": "01110 10001 10000 10000 10000 10001 01110",
    "D": "11110 10001 10001 10001 10001 10001 11110",
    "E": "11111 10000 10000 11110 10000 10000 11111",
    "F": "11111 10000 10000 11110 10000 10000 10000",
    "I": "01110 00100 00100 00100 00100 00100 01110",
    "N": "10001 10001 11001 10101 10011 10001 10001",
    "R": "11110 10001 10001 11110 10100 10010 10001",
    "S": "01111 10000 10000 01110 00001 00001 11110",
    "V": "10001 10001 10001 10001 10001 01010 00100",
    "X": "10001 10001 01010 00100 01010 10001 10001",
    "Y": "10001 10001 01010 00100 00100 00100 00100",
    "a": "00000 00000 01110 00001 01111 10001 01111",
    "c": "00000 00000 01110 10000 10000 10001 01110",
    "d": "00001 00001 01101 10011 10001 10001 01111",
    "e": "00000 00000 01110 10001 11111 10000 01110",
    "n": "00000 00000 10110 11001 10001 10001 10001",
    "s": "00000 00000 01110 10000 01110 00001 11110",
    "$": "00100 01111 10100 01110 00101 11110 00100",
    ">": "10000 01000 00100 00010 00100 01000 10000",
    ".": "00000 00000 00000 00000 00000 01100 01100",
    " ": "00000 00000 00000 00000 00000 00000 00000",
}
CHECK = ["0000001", "0000011", "1000110", "1101100", "0111000", "0010000"]

grid = [[BG] * W for _ in range(H)]


def put(x, y, color):
    if 0 <= x < W and 0 <= y < H:
        grid[y][x] = color


def rect(x0, y0, x1, y1, color):
    for y in range(y0, y1 + 1):
        for x in range(x0, x1 + 1):
            put(x, y, color)


def text(s, x, y, color, scale=1, shadow=None):
    """Returns the x after the text. `color` may be a function of the
    character's index, for the wordmark's gradient."""
    for i, ch in enumerate(s):
        rows = FONT[ch].split()
        c = color(i) if callable(color) else color
        for r, row in enumerate(rows):
            for col, bit in enumerate(row):
                if bit == "1":
                    for dy in range(scale):
                        for dx in range(scale):
                            px, py = x + col * scale + dx, y + r * scale + dy
                            if shadow:
                                put(px + 1, py + 1, shadow)
                            put(px, py, c)
        x += 6 * scale
    return x


def mix(a, b, t):
    rgb_a = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    rgb_b = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(p + (q - p) * t):02x}" for p, q in zip(rgb_a, rgb_b))


# ---------- the window ----------

rect(10, 6, 149, 73, FRAME)
rect(11, 7, 148, 12, TITLE_BAR)
rect(11, 13, 148, 72, BODY)
for cx, cy in ((10, 6), (149, 6), (10, 73), (149, 73)):   # rounded corners
    put(cx, cy, BG)
for i, color in enumerate(DOTS):
    rect(14 + i * 4, 9, 15 + i * 4, 10, color)

# ---------- the prompt ----------

x = text("$", 16, 17, PROMPT)
x = text(" cascadesec scan .", x, 17, TEXT)
rect(x + 1, 17, x + 5, 23, TEXT)                            # the cursor

# ---------- the wordmark ----------

WORD = "CASCADESEC"
word_w = len(WORD) * 12 - 2
wx = 11 + (138 - word_w) // 2
text(WORD, wx, 28, lambda i: mix(CYAN, GREEN, i / (len(WORD) - 1)), scale=2, shadow=SHADOW)

# ---------- the cascade ----------

STEPS = 7
for i in range(STEPS):
    t = i / (STEPS - 1)
    color = mix(CYAN, GREEN, t)
    sx, sy = wx + i * 14, 48 + i * 2
    rect(sx, sy, sx + 11, sy + 2, color)
    rect(sx, sy, sx + 11, sy, mix(color, "#ffffff", 0.35))    # lit top edge
    if i < STEPS - 1:                                         # spill onto the next step
        put(sx + 12, sy + 1, color)
        put(sx + 12, sy + 3, mix(color, BODY, 0.4))
cx, cy = wx + STEPS * 14 + 1, 48 + (STEPS - 1) * 2 - 3
for r, row in enumerate(CHECK):
    for c, bit in enumerate(row):
        if bit == "1":
            put(cx + c, cy + r, GREEN)

# ---------- the tagline ----------

TAG = "SCAN > FIX > VERIFY"
text(TAG, 11 + (138 - (len(TAG) * 6 - 1)) // 2, 64, DIM)


# ---------- output ----------

def svg():
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" '
             f'width="{W * SCALE}" height="{H * SCALE}" shape-rendering="crispEdges" '
             'role="img" aria-label="CascadeSec: a terminal running cascadesec scan, '
             'with a cascade of steps ending in a check">',
             f'<rect width="{W}" height="{H}" fill="{BG}"/>']
    for y, row in enumerate(grid):
        x = 0
        while x < W:
            color, start = row[x], x
            while x < W and row[x] == color:
                x += 1
            if color != BG:
                parts.append(f'<rect x="{start}" y="{y}" width="{x - start}" height="1" fill="{color}"/>')
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def png():
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    raw = bytearray()
    for row in grid:
        line = b"".join(bytes(int(c[i:i + 2], 16) for i in (1, 3, 5)) * SCALE for c in row)
        for _ in range(SCALE):
            raw += b"\x00" + line
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", W * SCALE, H * SCALE, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
            + chunk(b"IEND", b""))


if __name__ == "__main__":
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    (out / "cascadesec-banner.svg").write_text(svg(), encoding="utf-8", newline="\n")
    (out / "cascadesec-banner.png").write_bytes(png())
    print("wrote", out / "cascadesec-banner.svg", out / "cascadesec-banner.png")
