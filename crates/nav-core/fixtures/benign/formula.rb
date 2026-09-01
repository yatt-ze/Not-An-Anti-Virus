# Synthetic Homebrew-formula-style fixture. Legitimate installers commonly
# invoke curl to fetch release archives — this alone must not push a verdict
# above "no action" (see design doc §5.1's scoring invariant: no single
# generic signal may independently trigger a high-severity alert).

class ExampleTool
  def install
    system "curl -L -o release.tar.gz https://example.com/release.tar.gz"
    system "tar -xzf release.tar.gz"
    bin.install "example-tool"
  end
end
