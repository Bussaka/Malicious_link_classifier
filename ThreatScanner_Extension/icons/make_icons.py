"""Draws the extension icons: the UI's shield outline, filled blue, with a white check.

    python ThreatScanner_Extension/icons/make_icons.py

Rendered once at 1024px and downscaled, so the small toolbar sizes stay smooth.
"""
import os
from PIL import Image, ImageDraw

BLUE = (37, 106, 191, 255)      # #256abf, the UI's primary blue
WHITE = (255, 255, 255, 255)
SIZES = (16, 32, 48, 128)
CANVAS = 1024


def cubic(p0, p1, p2, p3, steps=40):
    return [tuple((1 - t) ** 3 * a + 3 * (1 - t) ** 2 * t * b + 3 * (1 - t) * t ** 2 * c + t ** 3 * d
                  for a, b, c, d in zip(p0, p1, p2, p3))
            for t in (i / steps for i in range(steps + 1))]


# The 24x24 SVG path used across the UI: M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z
SHIELD = (cubic((12, 22), (12, 22), (20, 18), (20, 12))
          + [(20, 5), (12, 2), (4, 5), (4, 12)]
          + cubic((4, 12), (4, 18), (12, 22), (12, 22)))
CHECK = [(8.6, 12.2), (11, 14.6), (15.6, 9.8)]


def to_canvas(points, scale, center=12):
    return [((x - center) * scale + CANVAS / 2, (y - center) * scale + CANVAS / 2) for x, y in points]


def draw_icon():
    image = Image.new('RGBA', (CANVAS, CANVAS), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    # The shield spans 20 units vertically; leave a small margin so it isn't clipped
    scale = CANVAS * 0.94 / 20
    draw.polygon(to_canvas(SHIELD, scale), fill=BLUE)
    check = to_canvas(CHECK, scale)
    width = int(scale * 2.1)
    draw.line(check, fill=WHITE, width=width, joint='curve')
    # Round the stroke ends
    for x, y in (check[0], check[-1]):
        draw.ellipse((x - width / 2, y - width / 2, x + width / 2, y + width / 2), fill=WHITE)
    return image


if __name__ == '__main__':
    out_dir = os.path.dirname(os.path.abspath(__file__))
    master = draw_icon()
    for size in SIZES:
        master.resize((size, size), Image.LANCZOS).save(os.path.join(out_dir, f'icon{size}.png'))
        print(f'icon{size}.png')
