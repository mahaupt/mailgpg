// ComposeSessionViewController.swift
// MailGPGExtension

import MailKit
import SwiftUI

/// Inline panel shown inside the compose window toolbar area.
/// Hosts ComposeSecurityView (SwiftUI) and drives it via a shared ComposeSessionState.
class ComposeSessionViewController: MEExtensionViewController {

    private let state: ComposeSessionState

    init(state: ComposeSessionState) {
        self.state = state
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) not supported — use init(state:)")
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        let hosting = NSHostingController(rootView: ComposeSecurityView(state: state))
        hosting.sizingOptions = .preferredContentSize

        addChild(hosting)

        hosting.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(hosting.view)

        NSLayoutConstraint.activate([
            hosting.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            hosting.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            hosting.view.topAnchor.constraint(equalTo: view.topAnchor),
            hosting.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        preferredContentSize = hosting.view.fittingSize
    }
}
