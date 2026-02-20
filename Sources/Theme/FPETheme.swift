import SwiftUI

// MARK: - FPE Brand Colors

extension Color {
    /// FPE Primary Orange: #F97316
    static let fpePrimary = Color(red: 249 / 255, green: 115 / 255, blue: 22 / 255)

    /// FPE Accent Amber/Gold: #F59E0B
    static let fpeAccent = Color(red: 245 / 255, green: 158 / 255, blue: 11 / 255)

    /// FPE Dark Navy: #0F172A
    static let fpeNavy = Color(red: 15 / 255, green: 23 / 255, blue: 42 / 255)

    /// FPE Destructive Red: #EF4444
    static let fpeDestructive = Color(red: 239 / 255, green: 68 / 255, blue: 68 / 255)

    /// FPE Success Green: #22C55E
    static let fpeSuccess = Color(red: 34 / 255, green: 197 / 255, blue: 94 / 255)

    /// FPE Muted Gray: #64748B
    static let fpeMuted = Color(red: 100 / 255, green: 116 / 255, blue: 139 / 255)

    /// FPE Border — adapts to light/dark mode
    static let fpeBorder = Color(.separatorColor)
}
