//go:build windows

package portscan

import "syscall"

func errnoRefused() syscall.Errno     { return 10061 }
func errnoReset() syscall.Errno       { return 10054 }
func errnoTimeout() syscall.Errno     { return 10060 }
func errnoHostUnreach() syscall.Errno { return 10065 }
func errnoNetUnreach() syscall.Errno  { return 10051 }
