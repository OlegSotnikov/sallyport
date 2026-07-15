# Sallyport brand assets

App icon + logo mark for reuse (e.g. the marketing site under `website/`).
Exported from `mac/Resources/AppIcon.icns`; the source render is
`mac/scripts/gen-icon.swift`.

© 2025-2026 Oleg Sotnikov · AppMaster

## The mark

A rounded-square (squircle) tile with a deep-indigo to electric-blue vertical
gradient and a centered white shield-with-lock glyph. The glyph is Apple's
SF Symbol `lock.shield.fill` at medium weight. Recreate it as a vector from SF
Symbols if you need a crisp SVG, or use `sallyport-glyph-white-1024.png`.

## Colors

| Role | sRGB hex | Notes |
|---|---|---|
| Gradient top (darkest) | `#121A47` | top of the tile |
| Gradient bottom (electric blue) | `#214DD9` | bottom of the tile; the primary brand blue |
| Tile base / shadow indigo | `#1A2452` | flat fallback if you can't use the gradient |
| Glyph | `#FFFFFF` | the shield, at ~97% opacity over the tile |

Primary brand gradient: `linear-gradient(180deg, #121A47 0%, #214DD9 100%)`.
Primary accent (for buttons/links on a light site): `#214DD9`.

## Files

| File | What | Use |
|---|---|---|
| `sallyport-icon.pdf` | Full icon, vector (scalable) | favicons, any size, convert to SVG |
| `sallyport-icon-1024.png` | Full icon, 1024×1024, transparent margins | hero / large |
| `sallyport-icon-512.png` / `-256` / `-128` | Full icon, downscaled | cards, nav, app-store-style |
| `sallyport-glyph-white-1024.png` | Shield glyph only, white on transparent | overlay on the brand tile / any dark surface |
| `sallyport.icns` | macOS icon container | reference / desktop use |

Notes:
- The full-icon PNGs keep the macOS ~10% transparent margin around the squircle
  (standard app-icon canvas). Trim if you want an edge-to-edge tile on the web.
- The glyph is white. Recolor it to `#214DD9` or another brand color for use on a
  light background.
