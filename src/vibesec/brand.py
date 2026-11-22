"""Logo do VibeSec no terminal: escudo com o V no recorte do topo e o S vazado, em degradê magenta → ciano."""

from __future__ import annotations

from rich.text import Text

# escudo: o topo tem o recorte em V, o S é o espaço vazio no corpo, a ponta fecha o V
SHIELD = [
    "█████▄   ▄█████",
    "███████▄███████",
    "████       ████",
    "███  ██████████",
    "████       ████",
    "██████████  ███",
    " ███       ███ ",
    "  ▀▀███████▀▀  ",
    "     ▀▀█▀▀     ",
]

WORD = [
    "██╗   ██╗██╗██████╗ ███████╗███████╗███████╗ ██████╗",
    "██║   ██║██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝",
    "██║   ██║██║██████╔╝█████╗  ███████╗█████╗  ██║     ",
    "╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║██╔══╝  ██║     ",
    " ╚████╔╝ ██║██████╔╝███████╗███████║███████╗╚██████╗",
    "  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝",
]

START = (0xD9, 0x46, 0xEF)  # magenta
END = (0x22, 0xD3, 0xEE)    # ciano


def _mix(t: float) -> str:
    r, g, b = (round(a + (z - a) * t) for a, z in zip(START, END, strict=True))
    return f"#{r:02x}{g:02x}{b:02x}"


def banner(version: str, tagline: str = "pentest de ponta a ponta para repositórios") -> Text:
    gap = "   "
    width = len(SHIELD[0]) + len(gap) + len(WORD[0])
    top = 1  # a palavra fica alinhada ao miolo do escudo
    out = Text("\n")
    for i, row in enumerate(SHIELD):
        j = i - top
        word = WORD[j] if 0 <= j < len(WORD) else ""
        if j == len(WORD) + 1:
            word = None
        line = " " + row + gap
        for k, ch in enumerate(line):
            out.append(ch, style=f"bold {_mix((k + i * 2) / (width + 16))}")
        if word is None:
            out.append(tagline, style="dim")
            out.append(f"  v{version}", style="bold #67E8F9")
        else:
            for k, ch in enumerate(word):
                out.append(ch, style=f"bold {_mix((len(line) + k) / width)}")
        out.append("\n")
    return out
