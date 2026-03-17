//
//  GPGLocator.swift
//  MailGPG
//
//  Created by Marcel Haupt on 17.03.26.
//
import Foundation

enum GPGLocatorError: Error {
    case notFound
}

struct GPGLocator {
    /// Alle bekannten Installationspfade, Reihenfolge ist Priorität
    static let candidatePaths = [
        "/opt/homebrew/bin/gpg",       // Apple Silicon Homebrew
        "/usr/local/bin/gpg",          // Intel Homebrew
        "/usr/local/MacGPG2/bin/gpg",  // GPG Suite
        "/usr/bin/gpg",                // System (selten)
        "/opt/homebrew/bin/gpg2",      // Alternative Namen
        "/usr/local/bin/gpg2",
    ]
    
    /// Findet den ersten verfügbaren GPG-Binary und gibt seinen Pfad zurück
    static func locate() throws -> String {
        for path in candidatePaths {
            if FileManager.default.isExecutableFile(atPath: path) {
                return path
            }
        }
        throw GPGLocatorError.notFound
    }
    
    /// Ruft `gpg --version` auf und gibt die Version zurück — damit testen wir ob es wirklich funktioniert
    static func version(at path: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["--version"]
      
        // Xcode Preview-Injektion aus der Umgebung entfernen
        var env = ProcessInfo.processInfo.environment
        env.removeValue(forKey: "DYLD_INSERT_LIBRARIES")
        process.environment = env
        
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        
        try process.run()
        process.waitUntilExit()
        
        // Beide Pipes lesen
        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""
        
        print("stdout: '\(stdout)'")
        print("stderr: '\(stderr)'")
        print("Exit code: \(process.terminationStatus)")
        
        // Ersten nicht-leeren String aus beiden nehmen
        let output = stdout.isEmpty ? stderr : stdout
        guard let firstLine = output.components(separatedBy: "\n").first(where: { !$0.isEmpty }) else {
            throw GPGLocatorError.notFound
        }
        return firstLine
    }
}
