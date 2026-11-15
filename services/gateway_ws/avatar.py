import hashlib
from pathlib import Path


def generate_brand_favicon_svg() -> str:
    """Generate a minimalist monochrome envelope emblem for ast.pp.ua."""
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
        '<rect x="1" y="1" width="30" height="30" rx="6" fill="#000000" stroke="#333333" stroke-width="1.5"/>'
        '<rect x="6" y="9" width="20" height="14" rx="2" fill="none" stroke="#FFFFFF" stroke-width="2"/>'
        '<path d="M7 10.5L16 17.5L25 10.5" fill="none" stroke="#FFFFFF" stroke-width="2" '
        'stroke-linecap="round" stroke-linejoin="round"/>'
        "</svg>"
    )


def ensure_brand_favicon(web_dir: Path) -> None:
    web_dir.mkdir(parents=True, exist_ok=True)
    favicon_path = web_dir / "favicon.svg"
    favicon_path.write_text(generate_brand_favicon_svg(), encoding="utf-8")


def generate_user_avatar_svg(username: str) -> str:
    """Generate a deterministic 5x5 symmetric monochrome avatar from username hash."""
    digest = hashlib.sha256(username.lower().encode("utf-8")).digest()
    rects: list[str] = []

    bit_idx = 0
    lit_count = 0
    for row in range(5):
        for col in range(3):
            byte_val = digest[bit_idx // 8]
            is_lit = bool((byte_val >> (bit_idx % 8)) & 1)
            bit_idx += 1
            if is_lit:
                lit_count += 1
                rects.append(f'<rect x="{col + 1}" y="{row + 1}" width="1" height="1" fill="#FFFFFF"/>')
                mirror_col = 4 - col
                if mirror_col != col:
                    rects.append(
                        f'<rect x="{mirror_col + 1}" y="{row + 1}" width="1" height="1" fill="#FFFFFF"/>'
                    )

    if lit_count == 0:
        rects.append('<rect x="3" y="3" width="1" height="1" fill="#FFFFFF"/>')

    body = "".join(rects)
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 7 7" shape-rendering="crispEdges">'
        '<rect width="7" height="7" rx="1.2" fill="#111111"/>'
        f"{body}"
        "</svg>"
    )
