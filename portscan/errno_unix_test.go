//go:build !windows

package portscan

import "syscall"

func errnoRefused() syscall.Errno     { return syscall.ECONNREFUSED }
func errnoReset() syscall.Errno       { return syscall.ECONNRESET }
func errnoTimeout() syscall.Errno     { return syscall.ETIMEDOUT }
func errnoHostUnreach() syscall.Errno { return syscall.EHOSTUNREACH }
func errnoNetUnreach() syscall.Errno  { return syscall.ENETUNREACH }
