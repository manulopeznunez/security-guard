import Foundation
import CryptoKit
import os.log

actor GeoIPService {
    static let shared = GeoIPService()

    // MARK: - Configuration

    private let endpoint = URL(string: "https://ip-api.com/batch?fields=status,country,countryCode,org,query")!
    private let maxBatchSize = 80
    private let rateLimitPerMinute = 40
    private let cacheTTL: TimeInterval = 3600  // 1 hour

    // MARK: - State

    private var cache: [String: CachedGeoResult] = [:]
    private var requestTimestamps: [Date] = []
    private var backoffUntil: Date = .distantPast
    private var consecutiveFailures = 0

    // MARK: - Types

    private struct CachedGeoResult {
        let country: String
        let countryCode: String
        let organization: String
        let cachedAt: Date

        var isExpired: Bool { Date().timeIntervalSince(cachedAt) > 3600 }
    }

    // MARK: - URLSession with Certificate Pinning

    private let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        config.waitsForConnectivity = false
        return URLSession(configuration: config, delegate: PinningDelegate(), delegateQueue: nil)
    }()

    // MARK: - Public API

    func resolve(ips: [String]) async -> [String: (country: String, countryCode: String, org: String)] {
        var results: [String: (country: String, countryCode: String, org: String)] = [:]
        var uncachedIPs: [String] = []

        for ip in ips {
            if let cached = cache[ip], !cached.isExpired {
                results[ip] = (cached.country, cached.countryCode, cached.organization)
            } else {
                uncachedIPs.append(ip)
            }
        }

        AuditLogger.network.info(
            "GeoIP: \(ips.count) requested, \(results.count) cached, \(uncachedIPs.count) to resolve"
        )

        guard !uncachedIPs.isEmpty else { return results }

        // Check backoff
        if Date() < backoffUntil {
            AuditLogger.network.warning("GeoIP: in backoff period, skipping API call")
            return results
        }

        // Rate limiting: trim old timestamps
        let oneMinuteAgo = Date().addingTimeInterval(-60)
        requestTimestamps.removeAll { $0 < oneMinuteAgo }

        // Process in batches
        for batchStart in stride(from: 0, to: uncachedIPs.count, by: maxBatchSize) {
            if requestTimestamps.count >= rateLimitPerMinute {
                AuditLogger.network.warning("GeoIP: rate limit reached, stopping batch processing")
                break
            }

            let batchEnd = min(batchStart + maxBatchSize, uncachedIPs.count)
            let batch = Array(uncachedIPs[batchStart..<batchEnd])

            do {
                let batchResults = try await fetchBatch(batch)
                for (ip, geo) in batchResults {
                    results[ip] = geo
                    cache[ip] = CachedGeoResult(
                        country: geo.country,
                        countryCode: geo.countryCode,
                        organization: geo.org,
                        cachedAt: Date()
                    )
                }
                consecutiveFailures = 0
                requestTimestamps.append(Date())
            } catch {
                consecutiveFailures += 1
                let backoffSeconds = min(pow(2.0, Double(consecutiveFailures)) * 5, 300)
                backoffUntil = Date().addingTimeInterval(backoffSeconds)
                AuditLogger.network.error(
                    "GeoIP batch failed: \(error.localizedDescription, privacy: .public). Backing off \(Int(backoffSeconds))s"
                )
                break
            }
        }

        return results
    }

    func pruneCache() {
        cache = cache.filter { !$0.value.isExpired }
    }

    // MARK: - Private

    private func fetchBatch(_ ips: [String]) async throws
        -> [String: (country: String, countryCode: String, org: String)]
    {
        let body = ips.map { ["query": $0, "fields": "status,country,countryCode,org,query"] }
        let jsonData = try JSONSerialization.data(withJSONObject: body)

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData

        let (data, response) = try await session.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }

        if httpResponse.statusCode == 429 {
            consecutiveFailures += 1
            let retryAfter = Double(httpResponse.value(forHTTPHeaderField: "Retry-After") ?? "60") ?? 60
            backoffUntil = Date().addingTimeInterval(retryAfter)
            throw URLError(.networkConnectionLost)
        }

        guard httpResponse.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }

        let geoResults = try JSONDecoder().decode([GeoInfo].self, from: data)
        var results: [String: (country: String, countryCode: String, org: String)] = [:]
        for geo in geoResults where geo.status == "success" {
            if let query = geo.query {
                results[query] = (geo.country ?? "Unknown", geo.countryCode ?? "?", geo.org ?? "")
            }
        }
        return results
    }
}

// MARK: - SPKI Certificate Pinning Delegate

private final class PinningDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {

    // SPKI SHA256 pin for ip-api.com's current public key (RSA 2048).
    // To regenerate:
    //   echo | openssl s_client -connect ip-api.com:443 -servername ip-api.com 2>/dev/null \
    //     | openssl x509 -pubkey -noout \
    //     | openssl pkey -pubin -outform DER \
    //     | openssl dgst -sha256 -binary | base64
    //
    // Update this hash when ip-api.com rotates their server key.
    private static let pinnedSPKIHashes: Set<String> = [
        "N7yhz1fS/yQbeoR3psw3Uj4e3ZydJ6FW5Ou+Xu02wj8=",
    ]

    // When true, a pin mismatch logs a critical warning but allows the
    // connection if standard TLS validation passes. This prevents bricking
    // the GeoIP feature when the server rotates keys.
    private static let allowFallbackOnPinMismatch = true

    // ASN.1 SPKI headers (prepended to raw key before hashing for RFC 7469 compatibility)
    private static let rsaSPKIHeader: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
    ]
    private static let ecSPKIHeader: [UInt8] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00,
    ]

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            return (.cancelAuthenticationChallenge, nil)
        }

        // Step 1: Standard TLS validation (hostname + chain + expiry)
        let policy = SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)
        SecTrustSetPolicies(serverTrust, policy)

        var error: CFError?
        let isTLSValid = SecTrustEvaluateWithError(serverTrust, &error)

        guard isTLSValid else {
            AuditLogger.security.error(
                "TLS validation failed for \(challenge.protectionSpace.host, privacy: .public): \(String(describing: error), privacy: .public)"
            )
            return (.cancelAuthenticationChallenge, nil)
        }

        // Step 2: SPKI pin verification on the leaf certificate
        switch verifySPKIPin(serverTrust: serverTrust, host: challenge.protectionSpace.host) {
        case .matched:
            return (.useCredential, URLCredential(trust: serverTrust))

        case .mismatch(let actualHash):
            AuditLogger.security.critical(
                "SPKI PIN MISMATCH for \(challenge.protectionSpace.host, privacy: .public). Got \(actualHash, privacy: .public). Possible MITM or key rotation."
            )
            if Self.allowFallbackOnPinMismatch {
                AuditLogger.security.warning("Fallback enabled: allowing connection despite pin mismatch")
                return (.useCredential, URLCredential(trust: serverTrust))
            }
            return (.cancelAuthenticationChallenge, nil)

        case .extractionFailed:
            AuditLogger.security.error(
                "Failed to extract public key for pin check on \(challenge.protectionSpace.host, privacy: .public)"
            )
            if Self.allowFallbackOnPinMismatch {
                return (.useCredential, URLCredential(trust: serverTrust))
            }
            return (.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - SPKI Pin Verification

    private enum PinResult {
        case matched
        case mismatch(actualHash: String)
        case extractionFailed
    }

    private func verifySPKIPin(serverTrust: SecTrust, host: String) -> PinResult {
        // Get the certificate chain and extract the leaf (index 0)
        guard let chain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let leaf = chain.first else {
            return .extractionFailed
        }

        // Extract the public key
        guard let publicKey = SecCertificateCopyKey(leaf) else {
            return .extractionFailed
        }

        // Compute SPKI hash
        guard let hashBase64 = spkiHash(for: publicKey) else {
            return .extractionFailed
        }

        if Self.pinnedSPKIHashes.contains(hashBase64) {
            return .matched
        }
        return .mismatch(actualHash: hashBase64)
    }

    /// Computes the SHA256 hash of the full SPKI (ASN.1 header + raw key) for RFC 7469 compatibility.
    private func spkiHash(for publicKey: SecKey) -> String? {
        var exportError: Unmanaged<CFError>?
        guard let rawKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            return nil
        }

        // Detect key type to select the correct ASN.1 header
        guard let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any],
              let keyType = attributes[kSecAttrKeyType as String] as? String else {
            return nil
        }

        let header: [UInt8]
        if keyType == (kSecAttrKeyTypeRSA as String) {
            header = Self.rsaSPKIHeader
        } else if keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
            header = Self.ecSPKIHeader
        } else {
            return nil
        }

        // Prepend ASN.1 header to raw key, then SHA256
        var spkiData = Data(header)
        spkiData.append(rawKeyData)
        let hash = SHA256.hash(data: spkiData)
        return Data(hash).base64EncodedString()
    }
}
