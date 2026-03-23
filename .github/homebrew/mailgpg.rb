# This file is the initial template for the mahaupt/homebrew-mailgpg tap.
# Copy it to: mahaupt/homebrew-mailgpg/Casks/mailgpg.rb
# Version and sha256 are updated automatically by the release GitHub Action.

cask "mailgpg" do
  version "1.0.0"
  sha256 "placeholder_updated_by_ci"

  url "https://github.com/mahaupt/mailgpg/releases/download/v#{version}/MailGPG-#{version}.dmg"
  name "MailGPG"
  desc "Native macOS Mail extension for GPG email encryption and signing"
  homepage "https://github.com/mahaupt/mailgpg"

  # Minimum macOS version for Mail extensions
  depends_on macos: ">= :monterey"

  # GPG binary and GUI-compatible pinentry are required for all operations
  depends_on formula: "gnupg"
  depends_on formula: "pinentry-mac"

  app "MailGPG.app"

  postflight do
    plist_path = "#{Dir.home}/Library/LaunchAgents/com.mahaupt.mailgpg.plist"
    plist_content = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>Label</key>
        <string>com.mahaupt.mailgpg</string>
        <key>ProgramArguments</key>
        <array>
          <string>/Applications/MailGPG.app/Contents/MacOS/MailGPG</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <true/>
        <key>StandardOutPath</key>
        <string>#{Dir.home}/Library/Logs/MailGPG/mailgpg.log</string>
        <key>StandardErrorPath</key>
        <string>#{Dir.home}/Library/Logs/MailGPG/mailgpg.log</string>
      </dict>
      </plist>
    XML

    FileUtils.mkdir_p("#{Dir.home}/Library/Logs/MailGPG")
    File.write(plist_path, plist_content)
    system_command "/bin/launchctl",
      args: ["bootstrap", "gui/#{Process.uid}", plist_path],
      print_stderr: false
  end

  uninstall_postflight do
    plist_path = "#{Dir.home}/Library/LaunchAgents/com.mahaupt.mailgpg.plist"
    system_command "/bin/launchctl",
      args: ["bootout", "gui/#{Process.uid}", plist_path],
      print_stderr: false
    FileUtils.rm_f(plist_path)
  end

  caveats <<~EOS
    MailGPG has been installed and the background service has been started.

    To finish setup, enable the Mail extension:
      System Settings → Privacy & Security → Extensions → Mail Extensions → MailGPG ✓

    Then open a compose window in Mail — the MailGPG panel will appear.

    If you already had Mail open, restart it first.
  EOS
end
