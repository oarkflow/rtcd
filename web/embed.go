// Package web holds the browser-side code that ships with rtcd, for programs
// that serve it (the example in examples/demo does).
package web

import "embed"

// Files are e2ee-core.js, e2ee-worker.js and chat-core.js.
//
//go:embed e2ee-core.js e2ee-worker.js chat-core.js
var Files embed.FS
