import Foundation

enum FormatUtils {
    static func bytes(_ value: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: value)
    }

    static func flag(for countryCode: String) -> String {
        guard countryCode.count == 2 else { return "" }
        let base: UInt32 = 127397
        let scalars = countryCode.uppercased().unicodeScalars.compactMap {
            UnicodeScalar(base + $0.value)
        }
        return scalars.map(String.init).joined()
    }

    /// Strips codesign authority boilerplate to extract the signer name.
    /// "Developer ID Application: SLACK TECHNOLOGIES L.L.C. (BQR82RBBHL)" → "Slack Technologies L.L.C."
    static func cleanAuthority(_ raw: String) -> String {
        // App Store apps: authority is exactly "Apple Mac OS Application Signing"
        if raw == "Apple Mac OS Application Signing" {
            return "App Store (Apple)"
        }
        var name = raw
        // Strip common prefixes
        for prefix in [
            "Developer ID Application: ",
            "Developer ID Installer: ",
            "Apple Development: ",
            "Apple Distribution: ",
            "3rd Party Mac Developer Application: ",
            "3rd Party Mac Developer Installer: ",
        ] {
            if name.hasPrefix(prefix) {
                name = String(name.dropFirst(prefix.count))
                break
            }
        }
        // Strip trailing team ID like " (BQR82RBBHL)"
        if let parenRange = name.range(of: #" \([A-Z0-9]{10}\)$"#, options: .regularExpression) {
            name = String(name[..<parenRange.lowerBound])
        }
        // Title-case: "SLACK TECHNOLOGIES L.L.C." → "Slack Technologies L.L.C."
        let words = name.split(separator: " ")
        let titled = words.map { word in
            let s = String(word)
            // Keep abbreviations like "L.L.C." or "LLC" as-is
            if s.contains(".") || s.count <= 3 && s == s.uppercased() { return s }
            return s.prefix(1).uppercased() + s.dropFirst().lowercased()
        }
        let result = titled.joined(separator: " ")
        // Never return empty if the input had content
        return result.isEmpty ? raw : result
    }

    /// Simplifies a raw reverse DNS hostname into a human-readable label.
    /// "mad41s13-in-f27.1e100.net" → "Google (1e100.net)"
    /// "server-52-84.cloudfront.net" → "Amazon CDN (cloudfront.net)"
    static func friendlyHostname(_ raw: String) -> String {
        guard !raw.isEmpty else { return "" }

        let lowered = raw.lowercased()

        // Known infrastructure → friendly name
        let knownDomains: [(suffix: String, label: String)] = [
            ("1e100.net", "Google"),
            ("google.com", "Google"),
            ("googleusercontent.com", "Google Cloud"),
            ("googlevideo.com", "YouTube"),
            ("youtube.com", "YouTube"),
            ("gstatic.com", "Google Static"),
            ("cloudfront.net", "Amazon CDN"),
            ("amazonaws.com", "AWS"),
            ("amazon.com", "Amazon"),
            ("akamaiedge.net", "Akamai CDN"),
            ("akamai.net", "Akamai CDN"),
            ("akamaitechnologies.com", "Akamai CDN"),
            ("cloudflare.com", "Cloudflare"),
            ("cloudflare-dns.com", "Cloudflare DNS"),
            ("fbcdn.net", "Meta/Facebook"),
            ("facebook.com", "Meta/Facebook"),
            ("whatsapp.net", "WhatsApp"),
            ("instagram.com", "Instagram"),
            ("apple.com", "Apple"),
            ("icloud.com", "iCloud"),
            ("icloud-content.com", "iCloud"),
            ("apple-dns.net", "Apple DNS"),
            ("mzstatic.com", "Apple CDN"),
            ("microsoft.com", "Microsoft"),
            ("msedge.net", "Microsoft CDN"),
            ("azure.com", "Azure"),
            ("office365.com", "Office 365"),
            ("office.com", "Office 365"),
            ("live.com", "Microsoft"),
            ("outlook.com", "Outlook"),
            ("skype.com", "Skype"),
            ("github.com", "GitHub"),
            ("github.io", "GitHub"),
            ("gitlab.com", "GitLab"),
            ("slack-msgs.com", "Slack"),
            ("slack.com", "Slack"),
            ("slackb.com", "Slack"),
            ("zoom.us", "Zoom"),
            ("zoomgov.com", "Zoom"),
            ("dropbox.com", "Dropbox"),
            ("dropboxapi.com", "Dropbox"),
            ("spotify.com", "Spotify"),
            ("spotifycdn.com", "Spotify"),
            ("scdn.co", "Spotify CDN"),
            ("twitch.tv", "Twitch"),
            ("twitchcdn.net", "Twitch"),
            ("twitter.com", "X/Twitter"),
            ("x.com", "X/Twitter"),
            ("anthropic.com", "Anthropic"),
            ("openai.com", "OpenAI"),
            ("notion.so", "Notion"),
            ("notion.com", "Notion"),
            ("linear.app", "Linear"),
            ("figma.com", "Figma"),
            ("vercel.app", "Vercel"),
            ("netlify.com", "Netlify"),
            ("heroku.com", "Heroku"),
            ("docker.com", "Docker"),
            ("docker.io", "Docker"),
        ]

        for entry in knownDomains {
            if lowered.hasSuffix(entry.suffix) || lowered == entry.suffix {
                return "\(entry.label) (\(entry.suffix))"
            }
        }

        // Not a known domain → extract root domain (last 2 parts)
        let parts = raw.split(separator: ".")
        if parts.count >= 2 {
            let root = parts.suffix(2).joined(separator: ".")
            return root
        }

        return raw
    }
}
