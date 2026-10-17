"""Generates the app icons at build time (run by the GitHub workflow before `tauri build`)."""
import os
from PIL import Image, ImageDraw

S = 512
out = os.path.join(os.path.dirname(__file__), "..", "src-tauri", "icons")
os.makedirs(out, exist_ok=True)

tile = Image.new("RGBA", (S, S), (0, 0, 0, 0))
ImageDraw.Draw(tile).rounded_rectangle((0, 0, S - 1, S - 1), radius=int(S * 0.22), fill=(5, 11, 9, 255))

grad = Image.new("RGBA", (S, S))
px = grad.load()
a, b = (47, 227, 143), (76, 201, 240)  # green -> blue
for y in range(S):
    for x in range(S):
        t = (x + y) / (2 * S - 2)
        px[x, y] = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)

pts = [(.22, .78), (.22, .22), (.36, .22), (.50, .52), (.64, .22), (.78, .22), (.78, .78),
       (.66, .78), (.66, .42), (.54, .70), (.46, .70), (.34, .42), (.34, .78)]
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).polygon([(x * S, y * S) for x, y in pts], fill=255)
tile.paste(grad, (0, 0), mask)

for name, size in (("icon.png", 512), ("128x128.png", 128), ("128x128@2x.png", 256), ("32x32.png", 32)):
    tile.resize((size, size), Image.LANCZOS).save(os.path.join(out, name))
tile.save(os.path.join(out, "icon.ico"), format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
tile.save(os.path.join(out, "icon.icns"), format="ICNS")
print("icons written to", os.path.abspath(out))
