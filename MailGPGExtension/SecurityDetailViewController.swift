// SecurityDetailViewController.swift
// MailGPGExtension

import MailKit
import SwiftUI

/// Detail sheet shown when the user taps the security banner.
/// Wraps SecurityDetailView (SwiftUI) inside an MEExtensionViewController (AppKit).
class SecurityDetailViewController: MEExtensionViewController {

    private let status: SecurityStatus

    init(status: SecurityStatus) {
        self.status = status
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) not supported — use init(status:)")
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        let detail = NSHostingController(rootView: SecurityDetailView(status: status))
        // Let SwiftUI's layout drive the popover size automatically
        detail.sizingOptions = .preferredContentSize

        addChild(detail)

        detail.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(detail.view)

        NSLayoutConstraint.activate([
            detail.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            detail.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            detail.view.topAnchor.constraint(equalTo: view.topAnchor),
            detail.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        // Forward the SwiftUI ideal size to Mail so it sizes the popover correctly
        preferredContentSize = detail.view.fittingSize
    }
}
