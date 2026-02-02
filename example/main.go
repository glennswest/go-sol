// Example SOL client usage
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gwest/go-sol"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <host> <username> <password>\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]
	username := os.Args[2]
	password := os.Args[3]

	session := sol.New(sol.Config{
		Host:     host,
		Port:     623,
		Username: username,
		Password: password,
		Timeout:  30 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("Connecting to %s...\n", host)
	if err := session.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Connect failed: %v\n", err)
		os.Exit(1)
	}
	defer session.Close()

	fmt.Println("Connected! Reading console output...")

	// Handle Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	// Read console output
	for {
		select {
		case data := <-session.Read():
			os.Stdout.Write(data)
		case err := <-session.Err():
			fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
			return
		case <-sig:
			fmt.Println("\nDisconnecting...")
			return
		}
	}
}
