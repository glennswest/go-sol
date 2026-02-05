# go-sol

A pure Go implementation of IPMI v2.0 Serial-Over-LAN (SOL) for reading and writing server console output over the network.

## Features

- **Pure Go** - No CGo, no external dependencies, no `ipmitool` required
- **RMCP+ Authentication** - Full IPMI v2.0 RAKP handshake with HMAC-SHA1
- **Bidirectional** - Read console output and write input to the BMC
- **High Throughput** - Queue-based buffering (10,000 packets) handles bursty boot output without data loss
- **Inactivity Detection** - ASF Presence Ping keepalives detect dead BMCs over UDP
- **Zero Dependencies** - Only Go standard library

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        go-sol                             │
├──────────────────────────────────────────────────────────┤
│                                                           │
│  Connect()                                                │
│  ┌──────────────────────────────────────────────────┐    │
│  │ 1. Get Channel Auth Capabilities (IPMI 1.5)      │    │
│  │ 2. Open RMCP+ Session                            │    │
│  │ 3. RAKP 1-4 Handshake (HMAC-SHA1)               │    │
│  │ 4. Deactivate existing SOL payload               │    │
│  │ 5. Activate SOL payload                          │    │
│  └──────────────────────────────────────────────────┘    │
│                                                           │
│  Runtime goroutines:                                      │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────┐        │
│  │ readLoop │  │writeLoop │  │ keepaliveLoop   │        │
│  │          │  │          │  │ (ASF Ping/Pong) │        │
│  └────┬─────┘  └────┬─────┘  └─────────────────┘        │
│       │              │                                    │
│       ▼              ▼                                    │
│   Read() chan    Write() method                           │
│                                                           │
└──────────────────────────────────────────────────────────┘
                       │
                       │ UDP port 623
                       ▼
                   BMC (IPMI)
```

### Protocol Stack

| Layer | Description |
|-------|-------------|
| **RMCP** | Remote Management Control Protocol (UDP 623) |
| **IPMI 2.0** | Intelligent Platform Management Interface session |
| **RAKP** | Remote Authenticated Key-Exchange Protocol (HMAC-SHA1) |
| **SOL** | Serial Over LAN payload with sequence/ACK tracking |

### Packet Flow

1. **readLoop** - Reads UDP packets in a tight loop (100ms read deadline), parses RMCP/SOL headers, sends ACKs, queues character data to an internal 10k buffer which drains to `Read()` channel
2. **writeLoop** - Reads from `Write()` calls, chunks data to BMC's max outbound size, builds SOL packets with sequence numbers
3. **keepaliveLoop** - Sends ASF Presence Pings at 1/3 of inactivity timeout interval. If no SOL packets received within the timeout, signals an error to trigger reconnection

## Security

**The credentials shown in examples (`ADMIN`/`ADMIN`) are placeholders only.** Always use strong, unique credentials for your BMC/IPMI accounts. Never commit real credentials to source control. Use environment variables or a secrets manager for production deployments.

## Usage

### Library

```go
import (
    "context"
    "fmt"
    "time"

    "github.com/gwest/go-sol"
)

session := sol.New(sol.Config{
    Host:              "192.168.11.10",
    Port:              623,
    Username:          "ADMIN",    // Example only - change to your credentials
    Password:          "ADMIN",    // Example only - change to your credentials
    Timeout:           30 * time.Second,
    InactivityTimeout: 5 * time.Minute, // 0 to disable
    Logf: func(format string, args ...interface{}) {
        fmt.Printf("[sol] "+format+"\n", args...)
    },
})

ctx := context.Background()
if err := session.Connect(ctx); err != nil {
    log.Fatal(err)
}
defer session.Close()

// Read console output
for data := range session.Read() {
    fmt.Print(string(data))
}

// Check for errors
if err := <-session.Err(); err != nil {
    log.Fatal(err)
}
```

### CLI Tool

```bash
# Build
go build -o sol ./cmd/sol

# Connect to a BMC
./sol -host 192.168.11.10 -user ADMIN -pass ADMIN

# With debug logging
./sol -host 192.168.11.10 -user ADMIN -pass ADMIN -v
```

```
Usage: sol -host <bmc-ip> -user <username> -pass <password> [-port 623] [-timeout 30s] [-v]
```

## API

### Config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Host` | string | required | BMC IP address or hostname |
| `Port` | int | 623 | IPMI UDP port |
| `Username` | string | required | IPMI username |
| `Password` | string | required | IPMI password |
| `Timeout` | time.Duration | 30s | Connection timeout for each handshake step |
| `InactivityTimeout` | time.Duration | 0 (disabled) | Close session if no SOL packets received for this duration |
| `Logf` | func(string, ...interface{}) | nil | Debug log callback |

### Session Methods

| Method | Description |
|--------|-------------|
| `New(Config) *Session` | Create a new session (not yet connected) |
| `Connect(ctx) error` | Establish RMCP+ session and activate SOL |
| `Read() <-chan []byte` | Channel receiving console output bytes |
| `Write([]byte) error` | Send input data to the console |
| `Err() <-chan error` | Channel receiving session errors |
| `Close() error` | Deactivate SOL and close session |

## File Structure

```
go-sol/
├── sol.go          # Public API: Session, Config, New, Connect, Read, Write, Close
├── session.go      # RMCP+ session: auth caps, open session, RAKP 1-4, close
├── payload.go      # SOL payload: readLoop, writeLoop, keepalive, ACK handling
├── rmcp.go         # Protocol primitives: headers, packet builders, HMAC, key generation
├── cmd/sol/        # CLI tool
│   └── main.go
├── example/        # Minimal usage example
│   └── main.go
└── go.mod
```

## BMC Requirements

- IPMI v2.0 with RMCP+ support
- SOL enabled (`ipmitool sol set enabled true`)
- UDP port 623 accessible from client
- Tested with Supermicro X9/X10/X11 BMCs
