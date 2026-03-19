// GPGServiceConnection.swift
// MailGPGExtension (extension only)

import Foundation

/// Manages the lifecycle of the XPC connection from the extension to the host app.
///
/// ## Ownership
/// `GPGService` (the actor) holds the single instance of this class.
/// Don't create it anywhere else.
///
/// ## Connection states
///
///   nil connection → connect() → connected
///                                    │
///                         interruptionHandler (host app crashed/restarted)
///                                    │
///                              XPC auto-reconnects on next message send
///                                    │
///                         invalidationHandler (host app quit cleanly)
///                                    │
///                              connection = nil → scheduleReconnect()
///                                    │
///                         after delay → connect() again (up to maxRetries)
///
final class GPGServiceConnection {

    // MARK: - Configuration

    private let serviceName = "com.mahaupt.mailgpg.gpgservice"
    private let maxRetries  = 3
    private let retryDelay  = Duration.seconds(2)

    // MARK: - State

    private var connection: NSXPCConnection?
    private var retryCount = 0

    /// `true` while a valid connection exists. Observed by `GPGService`
    /// to decide whether to surface a "host app not running" error.
    private(set) var isAvailable = false

    // Called by GPGService when availability changes, so it can update
    // any published state the UI observes.
    var onAvailabilityChanged: ((Bool) -> Void)?

    // MARK: - Public API

    /// Returns a proxy object the caller can cast to `GPGXPCProtocol` and call methods on.
    /// Throws `GPGXPCError.hostAppNotRunning` if no connection is available.
    func proxy() throws -> GPGXPCProtocol {
        if connection == nil { connect() }

        guard let conn = connection else {
            throw GPGXPCError.make(.hostAppNotRunning,
                message: "MailGPG host app is not running. Please open it to enable GPG operations.")
        }

        // `remoteObjectProxyWithErrorHandler` returns a proxy object.
        // Any XPC error that occurs mid-call is delivered to the error handler,
        // which we route into our availability tracking.
        let proxy = conn.remoteObjectProxyWithErrorHandler { [weak self] error in
            print("[GPGServiceConnection] Remote error: \(error)")
            self?.handleInvalidation()
        }

        // Force-cast is safe here: we configured the interface with GPGXPCProtocol,
        // so XPC guarantees the proxy conforms to it.
        return proxy as! GPGXPCProtocol
    }

    // MARK: - Connection management

    private func connect() {
        let conn = NSXPCConnection(machServiceName: serviceName)

        // Tell XPC what protocol the host app (remote side) implements.
        conn.remoteObjectInterface = NSXPCInterface(with: GPGXPCProtocol.self)

        // XPC needs to know about [String] parameters explicitly — without this,
        // any method that sends an array of strings across the boundary will be
        // rejected at runtime. We register each affected method here.
        configureArrayTypes(on: conn.remoteObjectInterface!)

        // Interruption = host app crashed but will restart. XPC buffers outgoing
        // calls and replays them once the host app reconnects. We just log it.
        conn.interruptionHandler = { [weak self] in
            print("[GPGServiceConnection] Connection interrupted (host app may have crashed)")
            self?.setAvailable(false)
        }

        // Invalidation = host app quit cleanly or was killed. The connection
        // object is now dead and must be replaced. We schedule a reconnect.
        conn.invalidationHandler = { [weak self] in
            print("[GPGServiceConnection] Connection invalidated (host app quit)")
            self?.handleInvalidation()
        }

        conn.resume()
        connection = conn
        retryCount = 0
        setAvailable(true)
        print("[GPGServiceConnection] Connected to \(serviceName)")
    }

    private func handleInvalidation() {
        connection = nil
        setAvailable(false)

        guard retryCount < maxRetries else {
            print("[GPGServiceConnection] Max retries reached — giving up")
            return
        }

        retryCount += 1
        print("[GPGServiceConnection] Scheduling reconnect attempt \(retryCount)/\(maxRetries)")

        // `Task` here runs in the Swift concurrency pool. We sleep, then try again.
        Task { [weak self] in
            guard let self else { return }
            try? await Task.sleep(for: retryDelay)
            self.connect()
        }
    }

    private func setAvailable(_ value: Bool) {
        isAvailable = value
        onAvailabilityChanged?(value)
    }

    // MARK: - XPC array type registration

    /// XPC is strict about collection types — you must declare that a parameter
    /// is an `NSArray` containing `NSString` elements, otherwise XPC refuses to
    /// send it across the process boundary and crashes at runtime.
    private func configureArrayTypes(on interface: NSXPCInterface) {
        // Metatypes (NSArray.self) are not directly Hashable in Swift.
        // Bridging via AnyObject gives us the Obj-C class object, which
        // IS an NSObject and therefore castable to AnyHashable.
        let stringArray = classSet(NSArray.self, NSString.self)

        // encrypt(data:recipientFingerprints:reply:) — argument index 1
        interface.setClasses(
            stringArray,
            for: #selector(GPGXPCProtocol.encrypt(data:recipientFingerprints:reply:)),
            argumentIndex: 1,
            ofReply: false
        )

        // signAndEncrypt(data:signerKeyID:recipientFingerprints:reply:) — argument index 2
        interface.setClasses(
            stringArray,
            for: #selector(GPGXPCProtocol.signAndEncrypt(data:signerKeyID:recipientFingerprints:reply:)),
            argumentIndex: 2,
            ofReply: false
        )
    }

    /// Builds a `Set<AnyHashable>` from Obj-C class objects.
    /// The bridge `as AnyObject` converts the Swift metatype to an Obj-C class
    /// object; the force-cast to `AnyHashable` succeeds because Obj-C class
    /// objects are NSObject instances, which are Hashable.
    private func classSet(_ classes: AnyClass...) -> Set<AnyHashable> {
        Set(classes.map { $0 as AnyObject as! AnyHashable })
    }
}
