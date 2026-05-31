import AppKit
import Foundation

private enum LauncherLog {
    static let directory: URL? = {
        guard let home = FileManager.default.homeDirectoryForCurrentUser as URL? else { return nil }
        return home.appendingPathComponent("Library/Logs/EndoriumFortAgent", isDirectory: true)
    }()

    static let fileURL: URL? = directory?.appendingPathComponent("launcher.log")

    static func write(_ message: String) {
        guard let directory, let fileURL else { return }
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            if !FileManager.default.fileExists(atPath: fileURL.path) {
                FileManager.default.createFile(atPath: fileURL.path, contents: nil)
            }
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let line = "[\(timestamp)] \(message)\n"
            let data = Data(line.utf8)
            let handle = try FileHandle(forWritingTo: fileURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: data)
        } catch {
            fputs("EndoriumFort launcher logging failed: \(error)\n", stderr)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let agentBinaryPath: String
    private var handledOpenEvent = false

    init(agentBinaryPath: String) {
        self.agentBinaryPath = agentBinaryPath
        LauncherLog.write("launcher.init agentBinaryPath=\(agentBinaryPath)")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        LauncherLog.write("launcher.didFinishLaunching args=\(CommandLine.arguments)")

        let launchArgs = CommandLine.arguments.dropFirst()
        if let deepLink = launchArgs.first(where: isDeepLink) {
            handledOpenEvent = true
            LauncherLog.write("launcher.deepLink.fromArgs url=\(deepLink)")
            launchAgent(with: deepLink)
            terminateSoon()
            return
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { [self] in
            if handledOpenEvent {
                return
            }
            LauncherLog.write("launcher.manualOpen.noDeepLink")
            showInstallHint()
            NSApp.terminate(nil)
        }
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        let deepLinks = urls.map(\.absoluteString).filter(isDeepLink)
        LauncherLog.write("launcher.openURLs count=\(urls.count) deepLinks=\(deepLinks.count)")
        guard !deepLinks.isEmpty else { return }

        handledOpenEvent = true
        for deepLink in deepLinks {
            LauncherLog.write("launcher.deepLink.fromOpenURLs url=\(deepLink)")
            launchAgent(with: deepLink)
        }
        terminateSoon()
    }

    private func launchAgent(with deepLink: String) {
        guard FileManager.default.isExecutableFile(atPath: agentBinaryPath) else {
            LauncherLog.write("launcher.agentBinary.missing path=\(agentBinaryPath)")
            showError(
                message: "Binaire agent introuvable",
                info: agentBinaryPath,
            )
            return
        }

        let task = Process()
        task.executableURL = URL(fileURLWithPath: agentBinaryPath)
        task.arguments = ["open-link", deepLink]
        LauncherLog.write("launcher.agentBinary.run path=\(agentBinaryPath) deepLink=\(deepLink)")

        do {
            try task.run()
            LauncherLog.write("launcher.agentBinary.started pid=\(task.processIdentifier)")
        } catch {
            LauncherLog.write("launcher.agentBinary.failed error=\(error.localizedDescription)")
            showError(
                message: "Impossible de lancer EndoriumFort Agent",
                info: error.localizedDescription,
            )
        }
    }

    private func terminateSoon() {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
            LauncherLog.write("launcher.terminate")
            NSApp.terminate(nil)
        }
    }

    private func showInstallHint() {
        LauncherLog.write("launcher.showInstallHint")
        let alert = NSAlert()
        alert.messageText = "EndoriumFort Agent est installe"
        alert.informativeText = "Cette app sert de handler pour les liens endoriumfort://. Ouvrez un lien depuis EndoriumFort pour lancer un tunnel."
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    private func showError(message: String, info: String) {
        LauncherLog.write("launcher.showError message=\(message) info=\(info)")
        let alert = NSAlert()
        alert.alertStyle = .critical
        alert.messageText = message
        alert.informativeText = info
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}

private func isDeepLink(_ value: String) -> Bool {
    value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased().hasPrefix("endoriumfort://")
}

let agentBinaryPath = Bundle.main.path(forAuxiliaryExecutable: "endoriumfort-agent-bin") ?? ""
let app = NSApplication.shared
let delegate = AppDelegate(agentBinaryPath: agentBinaryPath)
app.delegate = delegate
app.run()
