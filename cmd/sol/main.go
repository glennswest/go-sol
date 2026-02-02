// SOL CLI - Serial Over LAN console client
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	sol "github.com/gwest/go-sol"
)

func main() {
	host := flag.String("host", "", "BMC host IP address")
	user := flag.String("user", "ADMIN", "IPMI username")
	pass := flag.String("pass", "ADMIN", "IPMI password")
	port := flag.Int("port", 623, "IPMI port")
	timeout := flag.Duration("timeout", 30*time.Second, "Connection timeout")
	verbose := flag.Bool("v", false, "Verbose output")
	flag.Parse()

	if *host == "" {
		fmt.Fprintf(os.Stderr, "Usage: sol -host <bmc-ip> [-user USER] [-pass PASS]\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "Connecting to %s:%d as %s...\n", *host, *port, *user)
	}

	session := sol.New(sol.Config{
		Host:     *host,
		Port:     *port,
		Username: *user,
		Password: *pass,
		Timeout:  *timeout,
	})

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)

	if err := session.Connect(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "Connect failed: %v\n", err)
		os.Exit(1)
	}
	cancel()

	if *verbose {
		fmt.Fprintf(os.Stderr, "Connected! Press Ctrl+C to disconnect.\n")
	}

	// Handle Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Read console output
	for {
		select {
		case data, ok := <-session.Read():
			if !ok {
				if *verbose {
					fmt.Fprintf(os.Stderr, "\nConnection closed.\n")
				}
				session.Close()
				return
			}
			os.Stdout.Write(data)
		case err := <-session.Err():
			fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
			session.Close()
			os.Exit(1)
		case <-sig:
			if *verbose {
				fmt.Fprintf(os.Stderr, "\nDisconnecting...\n")
			}
			session.Close()
			return
		}
	}
}
