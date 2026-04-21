# VHS tape for the cartomancer README demo.
# Generate with: vhs examples/demo/demo.tape
# Output:       docs/assets/demo.gif

Output docs/assets/demo.gif

Set FontSize 13
Set Width 1280
Set Height 900
Set Theme "Dracula"
Set TypingSpeed 40ms
Set PlaybackSpeed 1.0
Set Padding 20
Set Shell "bash"

# Use the freshly-built release binary and the bundled fixture.
Hide
Type "export PATH=$(pwd)/target/release:$PATH"
Enter
Type "cd examples/demo/fixture"
Enter
Type "export RUST_LOG=error"
Enter
Type "clear"
Enter
Show

# Show what we're scanning.
Type "ls src/"
Sleep 400ms
Enter
Sleep 2s

# Real scan: opengrep finds patterns, cartog computes blast radius,
# cartomancer escalates severity by reachability + domain.
Type "cartomancer scan ."
Sleep 400ms
Enter

# Scan takes ~4s; then give the viewer time to read the output.
Sleep 12s
