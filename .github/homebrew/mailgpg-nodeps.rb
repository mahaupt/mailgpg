# This file is the initial template for the mahaupt/homebrew-mailgpg tap.
# Copy it to: mahaupt/homebrew-mailgpg/Casks/mailgpg-nodeps.rb
# Version and sha256 are updated automatically by the release GitHub Action.

cask "mailgpg-nodeps" do
  version "1.0.0"
  sha256 "placeholder_updated_by_ci"

  url "https://github.com/mahaupt/mailgpg/releases/download/v#{version}/MailGPG-#{version}.dmg"
  name "MailGPG"
  desc "Native macOS Mail extension for GPG email encryption and signing without Homebrew GPG dependencies"
  homepage "https://github.com/mahaupt/mailgpg"

  # Minimum macOS version
  depends_on macos: ">= :sonoma"

  app "MailGPG.app"

  postflight do
    plist_dir = "#{Dir.home}/Library/LaunchAgents"
    plist_path = "#{plist_dir}/com.mahaupt.mailgpg.plist"

    FileUtils.mkdir_p(plist_dir)

    executable = "#{appdir}/MailGPG.app/Contents/MacOS/MailGPG"
    plist_content = <<~XML
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>Label</key>
        <string>com.mahaupt.mailgpg</string>
        <key>AssociatedBundleIdentifiers</key>
        <string>com.mahaupt.MailGPG</string>
        <key>ProgramArguments</key>
        <array>
          <string>#{executable}</string>
        </array>
        <key>KeepAlive</key>
        <true/>
        <key>MachServices</key>
        <dict>
          <key>com.mahaupt.mailgpg.gpgservice</key>
          <true/>
        </dict>
      </dict>
      </plist>
    XML

    File.write(plist_path, plist_content)
    system_command "/bin/launchctl",
      args: ["bootstrap", "gui/#{Process.uid}", plist_path],
      print_stderr: false
  end

  uninstall_postflight do
    plist_path = "#{Dir.home}/Library/LaunchAgents/com.mahaupt.mailgpg.plist"
    if File.exist?(plist_path)
      system_command "/bin/launchctl",
        args: ["bootout", "gui/#{Process.uid}", plist_path],
        print_stderr: false
      FileUtils.rm_f(plist_path)
    end
  end

  caveats <<~EOS
    This cask does not install `gnupg` or `pinentry-mac`.
    Make sure a supported `gpg` binary and GUI pinentry are already installed.

    To finish setup, enable the Mail extension:
      Mail → Settings → Extensions → MailGPG ✓

    Restart Mail if it was already open.
  EOS
end
