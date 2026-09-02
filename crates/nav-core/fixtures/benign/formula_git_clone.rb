# Synthetic Homebrew-formula-style fixture: installs from a pinned git head
# rather than a release tarball — also an ordinary, widely-used formula
# shape, and a plain `make install` build step.
class ExampleGitTool
  head "https://github.com/example/example-git-tool.git", branch: "main"

  def install
    system "make", "PREFIX=#{prefix}", "install"
  end
end
