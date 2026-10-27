// Package web holds the browser-side code that ships with rtcd, for programs
// that serve it (the example in examples/demo does).
package web

import "embed"

// Files are e2ee-core.js, e2ee-worker.js, chat-core.js and chat-client.js.
//
//go:embed e2ee-core.js e2ee-worker.js chat-core.js chat-client.js
var Files embed.FS
