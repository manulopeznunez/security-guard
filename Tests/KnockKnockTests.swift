import Testing
@testable import MacSecurityGuard

struct KnockKnockTests {

    // MARK: - JSON Parsing

    @Test func parsesValidAppleSignedItem() {
        let json = """
        {
            "Launch Items": [
                {
                    "path": "/usr/libexec/softwareupdated",
                    "hashes": {"md5": "abc", "sha256": "def", "sha1": "ghi"},
                    "VT detection": "0/62",
                    "name": "softwareupdated",
                    "plist": "/System/Library/LaunchDaemons/com.apple.softwareupdated.plist",
                    "signature(s)": {
                        "signatureStatus": 0,
                        "signatureSigner": 1,
                        "signatureAuthorities": ["Software Signing", "Apple Code Signing CA"],
                        "signatureIdentifier": "com.apple.softwareupdated"
                    }
                }
            ]
        }
        """
        let result = KnockKnockViewModel.parseJSON(json)
        #expect(result.error == nil)
        #expect(result.totalItems == 1)
        #expect(result.appleSignedCount == 1)
        #expect(result.devIDSignedCount == 0)
        #expect(result.unsignedCount == 0)
        #expect(result.categories["Launch Items"]?.count == 1)
        #expect(result.flaggedItems.isEmpty)
    }

    @Test func parsesUnsignedItem() {
        let json = """
        {
            "Shell Configuration Files": [
                {
                    "path": "/Users/test/.zshrc",
                    "hashes": {"md5": "abc", "sha256": "def", "sha1": "ghi"},
                    "VT detection": "",
                    "name": ".zshrc",
                    "plist": "n/a",
                    "signature(s)": {
                        "signatureStatus": -67062,
                        "signatureSigner": 0,
                        "signatureAuthorities": [],
                        "signatureIdentifier": ""
                    }
                }
            ]
        }
        """
        let result = KnockKnockViewModel.parseJSON(json)
        #expect(result.unsignedCount == 1)
        #expect(result.flaggedItems.count == 1)
        #expect(result.flaggedItems.first?.name == ".zshrc")
    }

    @Test func parsesVTFlaggedItem() {
        let json = """
        {
            "Launch Items": [
                {
                    "path": "/tmp/malware",
                    "hashes": {"md5": "x", "sha256": "y", "sha1": "z"},
                    "VT detection": "5/62",
                    "name": "malware",
                    "plist": "",
                    "signature(s)": {
                        "signatureStatus": 0,
                        "signatureSigner": 3,
                        "signatureAuthorities": ["Developer ID Application: Evil Corp"],
                        "signatureIdentifier": "com.evil.malware"
                    }
                }
            ]
        }
        """
        let result = KnockKnockViewModel.parseJSON(json)
        #expect(result.vtFlaggedCount == 1)
        #expect(result.flaggedItems.count == 1)
        #expect(result.devIDSignedCount == 1)
    }

    @Test func parsesDevIDSignedItem() {
        let json = """
        {
            "Launch Items": [
                {
                    "path": "/Library/Application Support/Wireshark/ChmodBPF",
                    "hashes": {"md5": "a", "sha256": "b", "sha1": "c"},
                    "VT detection": "0/61",
                    "name": "ChmodBPF",
                    "plist": "/Library/LaunchDaemons/org.wireshark.ChmodBPF.plist",
                    "signature(s)": {
                        "signatureStatus": 0,
                        "signatureSigner": 3,
                        "signatureAuthorities": ["Developer ID Application: Wireshark Foundation (7Z6EMTD2C6)"],
                        "signatureIdentifier": "org.wireshark.ChmodBPF"
                    }
                }
            ]
        }
        """
        let result = KnockKnockViewModel.parseJSON(json)
        #expect(result.devIDSignedCount == 1)
        #expect(result.appleSignedCount == 0)
        #expect(result.unsignedCount == 0)
        #expect(result.flaggedItems.isEmpty)
    }

    @Test func handlesEmptyJSON() {
        let result = KnockKnockViewModel.parseJSON("{}")
        #expect(result.error == nil)
        #expect(result.totalItems == 0)
        #expect(result.categories.isEmpty)
    }

    @Test func handlesInvalidJSON() {
        let result = KnockKnockViewModel.parseJSON("not valid json at all")
        #expect(result.error != nil)
    }

    @Test func handlesMultipleCategories() {
        let json = """
        {
            "Launch Items": [
                {"path": "/a", "hashes": {}, "VT detection": "", "name": "a", "plist": "",
                 "signature(s)": {"signatureStatus": 0, "signatureSigner": 1, "signatureAuthorities": [], "signatureIdentifier": ""}}
            ],
            "Kernel Extensions": [
                {"path": "/b", "hashes": {}, "VT detection": "", "name": "b", "plist": "",
                 "signature(s)": {"signatureStatus": 0, "signatureSigner": 3, "signatureAuthorities": [], "signatureIdentifier": ""}}
            ],
            "Empty Category": []
        }
        """
        let result = KnockKnockViewModel.parseJSON(json)
        #expect(result.categories.count == 2)
        #expect(result.totalItems == 2)
        #expect(result.appleSignedCount == 1)
        #expect(result.devIDSignedCount == 1)
    }

    @Test func skipsMissingFieldsGracefully() {
        let json = """
        {
            "Launch Items": [
                {
                    "path": "/usr/bin/something",
                    "name": "something"
                }
            ]
        }
        """
        let result = KnockKnockViewModel.parseJSON(json)
        #expect(result.totalItems == 1)
        let item = result.categories["Launch Items"]?.first
        #expect(item?.name == "something")
        #expect(item?.md5 == "")
        #expect(item?.vtDetection == "")
        #expect(item?.signatureAuthorities.isEmpty == true)
    }
}
