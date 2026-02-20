import SwiftUI

struct BreachCheckView: View {
    @State private var viewModel = BreachCheckViewModel()
    @State private var showAPIKeySetup = false
    @State private var apiKeyInput = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()

            if !viewModel.apiKeyConfigured && viewModel.emailAccounts.isEmpty {
                apiKeySetupView
            } else if viewModel.emailAccounts.isEmpty && !viewModel.isScanning {
                emptyState
            } else {
                emailSection
                Divider()
                breachList
            }
        }
        .task {
            viewModel.apiKeyConfigured = BreachCheckViewModel.getAPIKey() != nil
            // Discover emails on load
            let discovered = BreachCheckViewModel.discoverEmails()
            if viewModel.emailAccounts.isEmpty {
                viewModel.emailAccounts = discovered
            }
        }
        .sheet(isPresented: $showAPIKeySetup) {
            apiKeySheet
        }
    }

    private var header: some View {
        HStack {
            Image(systemName: "exclamationmark.lock")
                .font(.title).foregroundStyle(.red)
            Text("Data Breaches").font(.title.bold())
            ScanDateLabel(scanner: .breachCheck)
            Spacer()
            if viewModel.isScanning {
                ProgressView().controlSize(.small)
                Text(viewModel.progress).font(.caption).foregroundStyle(.secondary)
            }
            Button(action: { showAPIKeySetup = true }) {
                Label(viewModel.apiKeyConfigured ? "API Key" : "Setup Key", systemImage: "key")
            }
            .controlSize(.small)
            Button(action: { Task { await viewModel.scan() } }) {
                Label("Scan", systemImage: "magnifyingglass")
            }
            .disabled(viewModel.isScanning || !viewModel.apiKeyConfigured)
        }
        .padding()
    }

    private var apiKeySetupView: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "exclamationmark.lock").font(.system(size: 48)).foregroundStyle(.secondary)
            Text("Data Breach Monitor").font(.title2.bold())
            Text("Check if your email accounts appear in known data breaches using the Have I Been Pwned API.")
                .font(.body).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 500)

            VStack(alignment: .leading, spacing: 8) {
                Text("To use this feature, you need an HIBP API key ($3.50/month):")
                    .font(.caption).foregroundStyle(.secondary)
                Text("1. Visit haveibeenpwned.com/API/Key")
                    .font(.caption)
                Text("2. Purchase an API key")
                    .font(.caption)
                Text("3. Enter it below")
                    .font(.caption)
            }
            .padding()
            .background(RoundedRectangle(cornerRadius: 8).fill(.quaternary))

            Button("Setup API Key") { showAPIKeySetup = true }
                .buttonStyle(.borderedProminent)

            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "exclamationmark.lock").font(.system(size: 48)).foregroundStyle(.secondary)
            Text("Press Scan to check your emails against known breaches").foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private var emailSection: some View {
        VStack(spacing: 0) {
            HStack(spacing: 16) {
                Label("\(viewModel.emailAccounts.count) emails", systemImage: "envelope")
                    .font(.caption)
                let totalBreaches = viewModel.breachResults.count
                if totalBreaches > 0 {
                    Label("\(totalBreaches) breaches found", systemImage: "exclamationmark.triangle.fill")
                        .font(.caption.bold()).foregroundStyle(.red)
                } else if !viewModel.isScanning && viewModel.apiKeyConfigured {
                    Label("No breaches found", systemImage: "checkmark.shield")
                        .font(.caption).foregroundStyle(.green)
                }
                Spacer()

                // Add email
                HStack(spacing: 4) {
                    TextField("Add email...", text: $viewModel.newEmailInput)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 200)
                        .onSubmit {
                            viewModel.addManualEmail(viewModel.newEmailInput)
                            viewModel.newEmailInput = ""
                        }
                    Button(action: {
                        viewModel.addManualEmail(viewModel.newEmailInput)
                        viewModel.newEmailInput = ""
                    }) {
                        Image(systemName: "plus.circle.fill")
                    }
                    .disabled(viewModel.newEmailInput.isEmpty)
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 6)

            // Email chips
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(viewModel.emailAccounts) { account in
                        HStack(spacing: 4) {
                            Image(systemName: account.source == "Apple ID" ? "apple.logo" :
                                    (account.source == "Mail.app" ? "envelope" :
                                        (account.source == "Keychain" ? "key" : "person")))
                                .font(.caption2)
                            Text(account.email).font(.caption2)
                            if account.breachCount > 0 {
                                Text("\(account.breachCount)")
                                    .font(.caption2.bold()).foregroundStyle(.white)
                                    .padding(.horizontal, 4).padding(.vertical, 1)
                                    .background(Color.red).clipShape(Capsule())
                            }
                            if account.source == "Manual" {
                                Button(action: { viewModel.removeManualEmail(account.email) }) {
                                    Image(systemName: "xmark").font(.caption2)
                                }.buttonStyle(.plain)
                            }
                        }
                        .padding(.horizontal, 8).padding(.vertical, 4)
                        .background(RoundedRectangle(cornerRadius: 6).fill(.quaternary))
                    }
                }
                .padding(.horizontal)
            }
            .padding(.bottom, 6)
        }
    }

    private var breachList: some View {
        List(viewModel.breachResults) { breach in
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "circle.fill")
                        .foregroundStyle(breach.risk.color).font(.caption2)
                    Text(breach.breachTitle).font(.headline)
                    if breach.isVerified {
                        Image(systemName: "checkmark.seal.fill").foregroundStyle(.blue).font(.caption)
                    }
                    Spacer()
                    Text(breach.email).font(.caption).foregroundStyle(.secondary)
                    Text(breach.breachDate).font(.caption).foregroundStyle(.tertiary)
                }

                if !breach.breachDomain.isEmpty {
                    Text(breach.breachDomain).font(.caption).foregroundStyle(.secondary)
                }

                // Data classes
                HStack(spacing: 4) {
                    ForEach(breach.dataClasses.prefix(8), id: \.self) { dataClass in
                        let isDangerous = dataClass.lowercased().contains("password") ||
                            dataClass.lowercased().contains("credit")
                        Text(dataClass)
                            .font(.caption2)
                            .foregroundStyle(isDangerous ? .red : .secondary)
                            .padding(.horizontal, 6).padding(.vertical, 2)
                            .background(
                                (isDangerous ? Color.red : Color.secondary).opacity(0.12)
                            )
                            .clipShape(Capsule())
                    }
                }

                HStack {
                    Text("\(breach.pwnCount.formatted()) accounts affected")
                        .font(.caption2).foregroundStyle(.tertiary)
                    Spacer()
                }
            }
            .padding(.vertical, 4)
        }
    }

    private var apiKeySheet: some View {
        VStack(spacing: 16) {
            Text("HIBP API Key").font(.title2.bold())
            Text("Enter your Have I Been Pwned API key. It will be stored securely in your macOS Keychain.")
                .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)

            SecureField("API Key", text: $apiKeyInput)
                .textFieldStyle(.roundedBorder)
                .frame(width: 400)

            HStack {
                Button("Cancel") { showAPIKeySetup = false }
                    .keyboardShortcut(.cancelAction)
                Button("Save") {
                    BreachCheckViewModel.setAPIKey(apiKeyInput)
                    viewModel.apiKeyConfigured = true
                    apiKeyInput = ""
                    showAPIKeySetup = false
                }
                .keyboardShortcut(.defaultAction)
                .disabled(apiKeyInput.isEmpty)
            }

            Divider()

            Button("Get API Key from haveibeenpwned.com") {
                NSWorkspace.shared.open(URL(string: "https://haveibeenpwned.com/API/Key")!)
            }
            .buttonStyle(.link)
        }
        .padding(24)
        .frame(width: 500)
    }
}
