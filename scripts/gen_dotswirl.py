import json
import math

grid_cols = 18
grid_rows = 18
spacing = 28
half_w = (grid_cols - 1) * spacing / 2
half_h = (grid_rows - 1) * spacing / 2

shapes = []

for row in range(grid_rows):
    for col in range(grid_cols):
        x = col * spacing - half_w
        y = row * spacing - half_h

        dist = math.sqrt(x * x + y * y)
        max_dist = math.sqrt(half_w ** 2 + half_h ** 2)

        # Skip corners to soften the square edges
        if dist > max_dist * 0.92:
            continue

        angle_rad = math.atan2(y, x)
        angle_deg = math.degrees(angle_rad)

        # Swirl: perpendicular to radial + tighter spiral near center
        swirl_strength = 1.2
        swirl_angle = angle_deg + 90 + (dist * swirl_strength)

        # Animation: oscillate the swirl
        anim_swing = 30 + (dist / max_dist) * 20
        mid_angle = swirl_angle + anim_swing * 0.6
        end_angle = swirl_angle + anim_swing

        # Opacity: fade edges, strong center
        edge_fade = max(0.25, 1.0 - (dist / max_dist) * 0.6)
        opacity = round(edge_fade * 80)

        # Dot length varies slightly with distance
        dot_len = 10 + (dist / max_dist) * 6

        dot = {
            "ty": "gr",
            "nm": f"D_{row}_{col}",
            "it": [
                {
                    "ty": "rc",
                    "nm": "R",
                    "p": {"a": 0, "k": [0, 0]},
                    "s": {"a": 0, "k": [round(dot_len, 1), 2.5]},
                    "r": {"a": 0, "k": 1}
                },
                {
                    "ty": "fl",
                    "nm": "F",
                    "c": {"a": 0, "k": [1, 1, 1, 1]},
                    "o": {"a": 0, "k": opacity}
                },
                {
                    "ty": "tr",
                    "p": {"a": 0, "k": [round(x, 1), round(y, 1)]},
                    "a": {"a": 0, "k": [0, 0]},
                    "s": {"a": 0, "k": [100, 100]},
                    "r": {
                        "a": 1,
                        "k": [
                            {"t": 0, "s": [round(swirl_angle, 1)], "e": [round(mid_angle, 1)]},
                            {"t": 180, "s": [round(mid_angle, 1)], "e": [round(end_angle, 1)]},
                            {"t": 360, "s": [round(end_angle, 1)]}
                        ]
                    },
                    "o": {"a": 0, "k": 100}
                }
            ]
        }
        shapes.append(dot)

# Group transform (gentle breathing drift)
shapes.append({
    "ty": "tr",
    "p": {
        "a": 1,
        "k": [
            {"t": 0, "s": [0, 0], "e": [8, -6]},
            {"t": 180, "s": [8, -6], "e": [-6, 8]},
            {"t": 360, "s": [-6, 8]}
        ]
    },
    "a": {"a": 0, "k": [0, 0]},
    "s": {"a": 0, "k": [100, 100]},
    "r": {"a": 0, "k": 0},
    "o": {"a": 0, "k": 100}
})

lottie = {
    "v": "5.7.4",
    "fr": 60,
    "ip": 0,
    "op": 360,
    "w": 1080,
    "h": 1920,
    "nm": "SecureLegion_DotSwirl",
    "ddd": 0,
    "assets": [],
    "layers": [
        {
            "ddd": 0,
            "ind": 1,
            "ty": 4,
            "nm": "SwirlField",
            "sr": 1,
            "ks": {
                "o": {"a": 0, "k": 100},
                "r": {"a": 0, "k": 0},
                "p": {"a": 0, "k": [540, 700, 0]},
                "a": {"a": 0, "k": [0, 0, 0]},
                "s": {"a": 0, "k": [100, 100, 100]}
            },
            "ao": 0,
            "shapes": [
                {
                    "ty": "gr",
                    "nm": "FieldGroup",
                    "it": shapes
                }
            ],
            "ip": 0,
            "op": 360,
            "st": 0,
            "bm": 0
        }
    ],
    "markers": []
}

out_path = "app/src/main/assets/welcome_dots.json"
with open(out_path, "w") as f:
    json.dump(lottie, f)

print(f"Generated {len(shapes) - 1} dots -> {out_path}")
