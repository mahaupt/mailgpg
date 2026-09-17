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
    ///
    /// GPG Suite kommt ZUERST: wenn es installiert ist, verwalten seine
    /// launchd-Agents den gpg-agent systemweit (org.gpgtools.macgpg2.fix startet
    /// SEINEN Agent beim Login, shutdown-gpg-agent beendet ihn bei Sleep/Lock).
    /// Jeder andere gpg-Client redet am Ende sowieso mit diesem Agent — ein
    /// neuerer Homebrew-Client an einem älteren MacGPG2-Agent ist genau der
    /// Versions-Skew, der sporadische Passphrase-/Entschlüsselungsfehler erzeugt.
    /// Mit GPG Suites eigenem gpg (und via toolPath dessen gpgconf) bleiben
    /// Client, Agent und die GPG-Keychain-App ein konsistenter Stack.
    static let candidatePaths = [
        "/usr/local/MacGPG2/bin/gpg",  // GPG Suite (MacGPG2)
        "/opt/homebrew/bin/gpg",       // Apple Silicon Homebrew
        "/usr/local/bin/gpg",          // Intel Homebrew
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
        
        // Ersten nicht-leeren String aus beiden nehmen
        let output = stdout.isEmpty ? stderr : stdout
        guard let firstLine = output.components(separatedBy: "\n").first(where: { !$0.isEmpty }) else {
            throw GPGLocatorError.notFound
        }
        return firstLine
    }
}
