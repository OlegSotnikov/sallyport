// Renders the 1024px Sallyport app icon.
// Usage: swift gen-icon.swift <out.png>
import AppKit

let size: CGFloat = 1024
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "AppIcon-1024.png"

let image = NSImage(size: NSSize(width: size, height: size))
image.lockFocus()

// Transparent canvas with 100px artwork margins.
let margin: CGFloat = 100
let rect = NSRect(x: margin, y: margin, width: size - 2*margin, height: size - 2*margin)
let radius: CGFloat = 185
let squircle = NSBezierPath(roundedRect: rect, xRadius: radius, yRadius: radius)

// Tile shadow.
NSGraphicsContext.current?.saveGraphicsState()
let shadow = NSShadow()
shadow.shadowColor = NSColor.black.withAlphaComponent(0.35)
shadow.shadowBlurRadius = 28
shadow.shadowOffset = NSSize(width: 0, height: -14)
shadow.set()
NSColor(calibratedRed: 0.10, green: 0.14, blue: 0.32, alpha: 1).setFill()
squircle.fill()
NSGraphicsContext.current?.restoreGraphicsState()

// Indigo-to-blue gradient.
let gradient = NSGradient(colors: [
    NSColor(calibratedRed: 0.07, green: 0.10, blue: 0.28, alpha: 1),
    NSColor(calibratedRed: 0.13, green: 0.30, blue: 0.85, alpha: 1),
])!
gradient.draw(in: squircle, angle: 90)

// Inner highlight.
let highlight = NSBezierPath(roundedRect: rect.insetBy(dx: 6, dy: 6), xRadius: radius - 6, yRadius: radius - 6)
NSColor.white.withAlphaComponent(0.10).setStroke()
highlight.lineWidth = 10
highlight.stroke()

// Centered white SF Symbol glyph.
let config = NSImage.SymbolConfiguration(pointSize: 430, weight: .medium)
if let symbol = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: nil)?
    .withSymbolConfiguration(config) {
    let tinted = NSImage(size: symbol.size)
    tinted.lockFocus()
    NSColor.white.set()
    let r = NSRect(origin: .zero, size: symbol.size)
    symbol.draw(in: r)
    r.fill(using: .sourceAtop)
    tinted.unlockFocus()
    let glyphW: CGFloat = 470
    let glyphH = glyphW * (tinted.size.height / tinted.size.width)
    let glyphRect = NSRect(x: (size - glyphW)/2, y: (size - glyphH)/2 - 8, width: glyphW, height: glyphH)
    tinted.draw(in: glyphRect, from: .zero, operation: .sourceOver, fraction: 0.97)
}

image.unlockFocus()

guard let tiff = image.tiffRepresentation,
      let rep = NSBitmapImageRep(data: tiff),
      let png = rep.representation(using: .png, properties: [:]) else {
    fputs("render failed\n", stderr); exit(1)
}
// Force 1024x1024 pixels regardless of screen scale.
rep.size = NSSize(width: size, height: size)
try! png.write(to: URL(fileURLWithPath: out))
print("wrote \(out)")
