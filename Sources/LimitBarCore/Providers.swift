import Foundation
import CryptoKit
import Security
import LocalAuthentication

public struct ClaudeProvider: UsageProvider {
    public let id = ProviderID.claude
    public init() {}

    public func fetch(allowInteraction: Bool) async throws -> UsageSnapshot {
        let credential = try await Task.detached(priority: .utility) {
            try ClaudeCredentials.load(allowInteraction: allowInteraction)
        }.value
        var request = URLRequest(url: URL(string: "https://api.anthropic.com/api/oauth/usage")!)
        request.timeoutInterval = 20
        request.setValue("Bearer " + credential.token, forHTTPHeaderField: "Authorization")
        request.setValue("oauth-2025-04-20", forHTTPHeaderField: "anthropic-beta")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 25
        config.httpShouldSetCookies = false
        config.urlCache = nil
        let session = URLSession(configuration: config, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let data: Data
        let response: URLResponse
        do { (data, response) = try await session.data(for: request) }
        catch { throw ProviderFailure(.network, "Couldn’t reach Claude. Check your connection and refresh.") }
        guard let http = response as? HTTPURLResponse else { throw ProviderFailure(.network, "No response from Claude.") }
        switch http.statusCode {
        case 200: return try UsageParser.claude(data: data, plan: credential.plan)
        case 401: throw ProviderFailure(.authentication, "Claude sign-in expired. Run claude auth login in Terminal, then refresh.")
        case 403: throw ProviderFailure(.authentication, "Claude denied usage access. Sign in with claude auth login using your subscription account.")
        case 429: throw ProviderFailure(.network, "Claude is rate limiting usage checks. Auto-refresh will retry in a few minutes.")
        default: throw ProviderFailure(.network, "Claude usage is unavailable (HTTP \(http.statusCode)). Try again later.")
        }
    }
}

private final class NoRedirects: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

private struct ClaudeCredentials {
    let token: String
    let plan: String
    static func load(allowInteraction: Bool) throws -> ClaudeCredentials {
        // Finder-launched apps don't inherit shell variables, so a custom profile can also be set with
        // `defaults write local.yukai.limitbar claudeConfigDir <path>`.
        let override = ProcessInfo.processInfo.environment["CLAUDE_CONFIG_DIR"]
            ?? UserDefaults.standard.string(forKey: "claudeConfigDir")
        let home = FileManager.default.homeDirectoryForCurrentUser
        let config = override.map { URL(fileURLWithPath: $0) } ?? home.appendingPathComponent(".claude")
        let file = config.appendingPathComponent(".credentials.json")
        if let data = try? Data(contentsOf: file), let credential = try? parse(data) { return credential }
        // Claude Code suffixes a custom profile's keychain entry with the first 8 hex digits of
        // SHA-256(config dir), so a custom profile never falls back to the global entry.
        let service = override.map { dir in
            "Claude Code-credentials-" + SHA256.hash(data: Data(dir.utf8)).map { String(format: "%02x", $0) }.joined().prefix(8)
        } ?? "Claude Code-credentials"
        let context = LAContext()
        context.interactionNotAllowed = !allowInteraction
        // Claude Code uses the legacy login keychain, whose ACL prompts do not honor
        // LAContext.interactionNotAllowed alone. Suppress legacy UI for background reads.
        var previousInteraction = DarwinBoolean(true)
        SecKeychainGetUserInteractionAllowed(&previousInteraction)
        if !allowInteraction { SecKeychainSetUserInteractionAllowed(false) }
        defer { if !allowInteraction { SecKeychainSetUserInteractionAllowed(previousInteraction.boolValue) } }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnData as String: true,
            kSecUseAuthenticationUI as String: allowInteraction ? kSecUseAuthenticationUIAllow : kSecUseAuthenticationUIFail,
            kSecUseAuthenticationContext as String: context
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            if status == errSecInteractionNotAllowed || status == errSecAuthFailed || status == errSecUserCanceled {
                throw ProviderFailure(.authentication, "Click Connect to allow access to your Claude Code sign-in in Keychain.")
            }
            throw ProviderFailure(.authentication, "Sign in with claude auth login in Terminal, then click Connect.")
        }
        return try parse(data)
    }
    static func parse(_ data: Data) throws -> ClaudeCredentials {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let oauth = root["claudeAiOauth"] as? [String: Any],
              let token = oauth["accessToken"] as? String, !token.isEmpty else {
            throw ProviderFailure(.authentication, "Claude Code has no subscription sign-in. Run claude auth login, then refresh.")
        }
        if let expiry = oauth["expiresAt"] as? Double, expiry / 1000 <= Date().timeIntervalSince1970 {
            throw ProviderFailure(.authentication, "Claude sign-in expired. Open Claude Code to renew it, then refresh.")
        }
        if let scopes = oauth["scopes"] as? [String], !scopes.contains("user:profile") {
            throw ProviderFailure(.authentication, "This Claude token cannot read usage. Run claude auth login with your subscription account.")
        }
        let plan = (oauth["subscriptionType"] as? String)?.capitalized ?? "Subscription"
        return ClaudeCredentials(token: token, plan: plan)
    }
}

public struct CodexProvider: UsageProvider {
    public let id = ProviderID.codex
    public init() {}
    public func fetch(allowInteraction: Bool) async throws -> UsageSnapshot {
        guard let path = ExecutableLocator.find("codex") else {
            throw ProviderFailure(.unavailable, "Install Codex CLI and run codex login, then refresh.")
        }
        return try await CodexRPC(executable: path).fetch()
    }
}

public enum ExecutableLocator {
    public static func find(_ name: String) -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let paths = [home + "/.local/bin", "/opt/homebrew/bin", "/usr/local/bin", home + "/.cargo/bin"]
            + (ProcessInfo.processInfo.environment["PATH"] ?? "").components(separatedBy: ":")
        return paths.map { $0 + "/" + name }.first { FileManager.default.isExecutableFile(atPath: $0) }
    }
}

// A bounded, read-only RPC exchange. No thread, inference turn, or login is started.
private final class CodexRPC: @unchecked Sendable {
    let executable: String
    let process = Process()
    let input = Pipe()
    let output = Pipe()
    let queue = DispatchQueue(label: "app.limitbar.codex-rpc")
    var continuation: CheckedContinuation<UsageSnapshot, Error>?
    var buffer = Data()
    var responseData: Data?
    var plan: String?
    var accountDone = false
    var timeout: DispatchWorkItem?
    var finished = false

    init(executable: String) { self.executable = executable }
    func fetch() async throws -> UsageSnapshot {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { self.start(continuation) }
        }
    }
    func start(_ continuation: CheckedContinuation<UsageSnapshot, Error>) {
        self.continuation = continuation
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = ["app-server", "--listen", "stdio://"]
        process.standardInput = input; process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.currentDirectoryURL = FileManager.default.homeDirectoryForCurrentUser
        var environment = ProcessInfo.processInfo.environment
        environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:" + (environment["PATH"] ?? "")
        process.environment = environment
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self else { return }
            self.queue.async { self.receive(data) }
        }
        let timeout = DispatchWorkItem { [weak self] in
            self?.finish(.failure(ProviderFailure(.network, "Codex usage check timed out. Check your connection and refresh.")))
        }
        self.timeout = timeout
        queue.asyncAfter(deadline: .now() + 30, execute: timeout)
        do {
            try process.run()
            try send(["id": 1, "method": "initialize", "params": ["clientInfo": ["name": "limitbar", "title": "LimitBar", "version": "1.0.0"]]])
        } catch {
            finish(.failure(ProviderFailure(.unavailable, "Couldn’t start Codex CLI. Check your Codex installation.")))
        }
    }
    func send(_ object: [String: Any]) throws {
        var data = try JSONSerialization.data(withJSONObject: object)
        data.append(10)
        try input.fileHandleForWriting.write(contentsOf: data)
    }
    func receive(_ data: Data) {
        guard !finished else { return }
        guard !data.isEmpty else {
            finish(.failure(ProviderFailure(.unavailable, "Codex CLI closed before returning limits. Check codex login status in Terminal.")))
            return
        }
        buffer.append(data)
        guard buffer.count <= 2_000_000 else {
            finish(.failure(ProviderFailure(.malformed, "Codex returned an oversized response."))); return
        }
        while let end = buffer.firstIndex(of: 10), !finished {
            let line = Data(buffer[..<end])
            buffer.removeSubrange(...end)
            guard let message = try? JSONSerialization.jsonObject(with: line) as? [String: Any], let id = message["id"] as? Int else { continue }
            do {
                if message["error"] != nil {
                    if id == 2 { accountDone = true }
                    else {
                        throw ProviderFailure(.authentication, "Codex couldn’t read subscription limits. Run codex login with your ChatGPT account, then refresh.")
                    }
                } else if id == 1 {
                    try send(["method": "initialized"])
                    try send(["id": 2, "method": "account/read", "params": ["refreshToken": false]])
                    try send(["id": 3, "method": "account/rateLimits/read"])
                } else if id == 2 {
                    let result = message["result"] as? [String: Any]
                    let account = result?["account"] as? [String: Any]
                    plan = account?["chatgptPlanType"] as? String
                    accountDone = true
                } else if id == 3 { responseData = line }
                if let responseData, accountDone {
                    finish(.success(try UsageParser.codex(data: responseData, plan: plan)))
                }
            } catch { finish(.failure(error)) }
        }
    }
    func finish(_ result: Result<UsageSnapshot, Error>) {
        guard !finished else { return }
        finished = true
        timeout?.cancel(); timeout = nil
        output.fileHandleForReading.readabilityHandler = nil
        try? input.fileHandleForWriting.close()
        if process.isRunning {
            process.terminate()
            let child = process
            DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
                if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            }
        }
        continuation?.resume(with: result); continuation = nil
    }
}
