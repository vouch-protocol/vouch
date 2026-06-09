"""Generate a 128x128 PNG icon for the VS Code extension.

A shield silhouette in burgundy with a white V inside, on a parchment
background. Matches the vouch-protocol.com palette.
"""
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

SIZE = 128
BG = (245, 237, 221, 255)      # parchment
SHIELD = (123, 27, 49, 255)    # burgundy
INK = (255, 255, 255, 255)     # white V

img = Image.new("RGBA", (SIZE, SIZE), BG)
draw = ImageDraw.Draw(img)

# Shield outline: simple polygon, top wide, bottom pointed.
pad = 14
shield = [
    (pad, pad + 6),
    (SIZE - pad, pad + 6),
    (SIZE - pad, int(SIZE * 0.55)),
    (SIZE // 2, SIZE - pad),
    (pad, int(SIZE * 0.55)),
]
draw.polygon(shield, fill=SHIELD)

# Inset V: simpler than drawing a glyph; two filled triangles.
v_top_y = 38
v_bot_y = 92
v_w = 10
# Left arm
left = [
    (38, v_top_y),
    (48, v_top_y),
    (SIZE // 2 + 2, v_bot_y),
    (SIZE // 2 - 4, v_bot_y),
]
draw.polygon(left, fill=INK)
# Right arm
right = [
    (90, v_top_y),
    (80, v_top_y),
    (SIZE // 2 - 2, v_bot_y),
    (SIZE // 2 + 4, v_bot_y),
]
draw.polygon(right, fill=INK)

out = Path(__file__).parent / "images" / "icon.png"
out.parent.mkdir(parents=True, exist_ok=True)
img.save(out, "PNG", optimize=True)
print(f"wrote {out} ({out.stat().st_size} bytes)")
