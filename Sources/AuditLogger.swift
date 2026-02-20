import os.log

enum AuditLogger {
    static let subsystem = "com.macsecurityguard.app"

    static let shell    = Logger(subsystem: subsystem, category: "shell")
    static let network  = Logger(subsystem: subsystem, category: "network")
    static let database = Logger(subsystem: subsystem, category: "database")
    static let security = Logger(subsystem: subsystem, category: "security")
    static let audit    = Logger(subsystem: subsystem, category: "audit")
    static let app      = Logger(subsystem: subsystem, category: "app")
}
