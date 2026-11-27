THEMES = {
    "Antechamber": ("gate-ante", "Antechamber", "🚪 🚪 🚪"),
    "Mirror": ("gate-mirror", "Mirror Gate", "🪞 🪞 🪞"),
    "Echo": ("gate-echo", "Echo Gate", "🔉 🔉 🔉"),
    "Rift": ("gate-rift", "Rift Gate", "🕳️ 🕳️ 🕳️"),
    "Glyph": ("gate-emoji", "Glyph Gate", "🔣 🔣 🔣"),
    "Labyrinth": ("gate-lab", "Labyrinth", "🧩 A new corridor twists into view... 🧩"),
    "OK": ("gate-ok", "Flow Gate", "⏱️ Your timing seems human... ⏱️"),
    "Too-Fast": ("gate-throttle", "Throttle Gate", "🌪️ That was a swift response! The door hesitates... 🌪️"),
}

DEFAULT_THEME = ("gate-ante", "Antechamber", "🚪 🚪 🚪")

def resolve(gate_name: str | None, reason: str | None):
    if not gate_name:
        cls, title, line = DEFAULT_THEME
        return cls, (title or ""), line

    cls, title, line = THEMES.get(gate_name, ("gate-generic", gate_name, DEFAULT_THEME[2]))
    if reason:
        line = f"{line} <span class='why'>({reason})</span>"
    return cls, title, line