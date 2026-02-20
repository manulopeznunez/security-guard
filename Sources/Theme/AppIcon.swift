import SwiftUI
import AppKit

/// Generates the app icon programmatically using the FPE brand colors
/// with a security shield + lock overlay.
@MainActor
enum AppIcon {

    /// macOS icon grid inset: icon shape is ~80% of the canvas.
    private static let iconInset: CGFloat = 0.88

    static func generate() -> NSImage {
        let size: CGFloat = 512
        let renderer = ImageRenderer(content: iconView(size: size))
        renderer.scale = 2.0
        guard let cgImage = renderer.cgImage else {
            return NSImage(size: NSSize(width: size, height: size))
        }
        return NSImage(cgImage: cgImage, size: NSSize(width: size, height: size))
    }

    private static func iconView(size: CGFloat) -> some View {
        let s = size * iconInset
        return ZStack {
            // Background: same FPE gradient rounded rectangle
            RoundedRectangle(cornerRadius: s * 0.22)
                .fill(
                    LinearGradient(
                        colors: [Color.fpePrimary, Color.fpeAccent],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )

            // Subtle inner border for depth
            RoundedRectangle(cornerRadius: s * 0.22)
                .strokeBorder(.white.opacity(0.2), lineWidth: s * 0.01)

            // Security shield + lock icon
            Image(systemName: "lock.shield.fill")
                .font(.system(size: s * 0.55, weight: .medium))
                .foregroundStyle(.white.opacity(0.95))
                .offset(y: -s * 0.02)

            // "FPE" text at bottom
            Text("FPE")
                .font(.system(size: s * 0.1, weight: .heavy))
                .foregroundStyle(.white.opacity(0.85))
                .offset(y: s * 0.35)
        }
        .frame(width: s, height: s)
        .frame(width: size, height: size)
    }
}
