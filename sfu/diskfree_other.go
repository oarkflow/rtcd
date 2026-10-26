//go:build !unix

package sfu

func freeBytes(string) (uint64, bool) { return 0, false }
