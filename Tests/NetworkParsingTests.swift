import Testing
@testable import MacSecurityGuard

struct NetworkParsingTests {

    // MARK: - isLocalAddress

    @Test func privateIPv4_192_168() {
        #expect(NetworkMonitorViewModel.isLocalAddress("192.168.0.1") == true)
        #expect(NetworkMonitorViewModel.isLocalAddress("192.168.1.100") == true)
    }

    @Test func privateIPv4_10() {
        #expect(NetworkMonitorViewModel.isLocalAddress("10.0.0.1") == true)
        #expect(NetworkMonitorViewModel.isLocalAddress("10.255.255.255") == true)
    }

    @Test func privateIPv4_172() {
        #expect(NetworkMonitorViewModel.isLocalAddress("172.16.0.1") == true)
        #expect(NetworkMonitorViewModel.isLocalAddress("172.31.255.255") == true)
    }

    @Test func localhost() {
        #expect(NetworkMonitorViewModel.isLocalAddress("127.0.0.1") == true)
        #expect(NetworkMonitorViewModel.isLocalAddress("localhost") == true)
    }

    @Test func ipv6Local() {
        #expect(NetworkMonitorViewModel.isLocalAddress("::1") == true)
        #expect(NetworkMonitorViewModel.isLocalAddress("fe80::1") == true)
    }

    @Test func listeningWildcard() {
        #expect(NetworkMonitorViewModel.isLocalAddress("*") == true)
    }

    @Test func publicIPv4IsNotLocal() {
        #expect(NetworkMonitorViewModel.isLocalAddress("8.8.8.8") == false)
        #expect(NetworkMonitorViewModel.isLocalAddress("1.1.1.1") == false)
        #expect(NetworkMonitorViewModel.isLocalAddress("203.0.113.1") == false)
    }

    @Test func emptyStringIsNotLocal() {
        #expect(NetworkMonitorViewModel.isLocalAddress("") == false)
    }

    // MARK: - parseAddressPort

    @Test func ipv4WithPort() {
        let (addr, port) = NetworkMonitorViewModel.parseAddressPort("192.168.0.11:55289")
        #expect(addr == "192.168.0.11")
        #expect(port == "55289")
    }

    @Test func ipv6WithPort() {
        let (addr, port) = NetworkMonitorViewModel.parseAddressPort("[fe80::1]:443")
        #expect(addr == "fe80::1")
        #expect(port == "443")
    }

    @Test func addressOnly() {
        let (addr, port) = NetworkMonitorViewModel.parseAddressPort("192.168.0.1")
        #expect(addr == "192.168.0.1")
        #expect(port == "")
    }

    @Test func emptyInput() {
        let (addr, port) = NetworkMonitorViewModel.parseAddressPort("")
        #expect(addr == "")
        #expect(port == "")
    }
}
