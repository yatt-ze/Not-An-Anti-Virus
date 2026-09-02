# Synthetic Homebrew-formula-style fixture: a CMake-based C++ tool, built
# from a local checkout rather than a downloaded release — an ordinary
# formula shape distinct from the existing tarball-fetch fixture.
class ExampleCmakeTool
  def install
    system "cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Release"
    system "cmake", "--build", "build"
    bin.install "build/example-cmake-tool"
  end

  test do
    system bin/"example-cmake-tool", "--version"
  end
end
