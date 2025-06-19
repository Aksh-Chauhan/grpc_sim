package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os" // Added for os.Getenv
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"grpc_gossip_simulator_fv/gossip" // Assuming 'gossip' package is correctly generated
)

// serverConfig holds configuration for a gRPC server/client instance.
type serverConfig struct {
	id          string // Unique identifier for the server/client
	listenIP    string // Specific IP address for the server to listen on
	listenPort  string // Port for the server to listen on
	connectIP   string // Specific IP address for the client to connect to
	connectPort string // Port for the client to connect to
}

// gossipServer implements the gRPC GossipServiceServer interface.
type gossipServer struct {
	gossip.UnimplementedGossipServiceServer // Embed for forward compatibility
	config                                  serverConfig
}

// NewGossipServer creates and returns a new gossipServer instance.
func NewGossipServer(cfg serverConfig) *gossipServer {
	return &gossipServer{
		config: cfg,
	}
}

// GossipStream implements the bidirectional streaming RPC.
// It sends messages at 3-second intervals and receives messages from the peer.
func (s *gossipServer) GossipStream(stream gossip.GossipService_GossipStreamServer) error {
	log.Printf("%s: GossipStream opened by peer.", s.config.id)

	// Goroutine to handle receiving messages from the stream.
	go func() {
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				log.Printf("%s: Peer closed the receive stream.", s.config.id)
				return
			}
			if err != nil {
				log.Printf("%s: Error receiving message from stream: %v", s.config.id, err)
				return
			}
			log.Printf("%s: Received message from %s: \"%s\"", s.config.id, req.GetSenderIp(), req.GetContent())
		}
	}()

	ticker := time.NewTicker(3 * time.Second) // Send a message every 3 seconds
	defer ticker.Stop()
	msgCount := 0

	// Main loop for sending messages.
	for {
		select {
		case <-stream.Context().Done(): // Check if the stream context is cancelled (e.g., peer disconnected)
			log.Printf("%s: Stream context cancelled, closing send stream: %v", s.config.id, stream.Context().Err())
			return stream.Context().Err()
		case <-ticker.C: // On ticker tick, send a new message
			msgCount++
			content := fmt.Sprintf("Hello from %s (msg %d)", s.config.id, msgCount)
			err := stream.Send(&gossip.GossipMessage{
				SenderIp:   s.config.id,        // Assuming s.config.id is the sender's IP
				ReceiverIp: s.config.connectIP, // Retrieve receiver's IP from context or set it appropriately
				Content:    content,
			})
			if err != nil {
				log.Printf("%s: Error sending message to stream: %v", s.config.id, err)
				return err
			}
			log.Printf("%s: Sent message to peer: \"%s\"", s.config.id, content)
		}
	}
}

// startServer initializes and starts a gRPC server with mTLS.
func startServer(cfg serverConfig, wg *sync.WaitGroup, KeylogFile io.Writer) {
	defer wg.Done()

	// Load server's certificate and key without quotes
	serverCert, err := tls.LoadX509KeyPair(fmt.Sprintf("/app/certs/%s.crt", cfg.id), fmt.Sprintf("/app/certs/%s.key", cfg.id))
	if err != nil {
		log.Fatalf("%s: Failed to load server certificate and key: %v", cfg.id, err)
	}

	// Load CA certificate for client authentication
	caCert, err := os.ReadFile("/app/certs/ca.crt")
	if err != nil {
		log.Fatalf("%s: Failed to read CA certificate: %v", cfg.id, err)
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("%s: Failed to append CA certificate to pool.", cfg.id)
	}

	// Configure TLS for the server with client authentication (mTLS)
	tlsConfig := &tls.Config{
		Certificates:           []tls.Certificate{serverCert},
		ClientCAs:              caCertPool,
		ClientAuth:             tls.RequireAndVerifyClientCert, // Require client cert and verify against CA
		MinVersion:             tls.VersionTLS12,
		KeyLogWriter:           KeylogFile,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}

	// Create gRPC server credentials from TLS config
	creds := credentials.NewTLS(tlsConfig)

	listenAddr := fmt.Sprintf("%s:%s", cfg.listenIP, cfg.listenPort)
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("%s: Failed to listen on %s: %v", cfg.id, listenAddr, err)
	}

	// Create a new gossip server instance
	gossipServer := NewGossipServer(cfg) // Ensure this function is updated to handle the new message structure

	s := grpc.NewServer(grpc.Creds(creds)) // Use TLS credentials
	gossip.RegisterGossipServiceServer(s, gossipServer)

	log.Printf("%s: Server listening on %s with mTLS", cfg.id, listenAddr)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("%s: Failed to serve: %v", cfg.id, err)
	}
}

// startClient initializes a gRPC client with mTLS.
// startClient initializes a gRPC client with mTLS.
func startClient(cfg serverConfig, wg *sync.WaitGroup, KeylogFile io.Writer) {
	defer wg.Done()

	time.Sleep(2 * time.Second)

	// Load client's certificate and key
	clientCert, err := tls.LoadX509KeyPair("/app/certs/client.crt", "/app/certs/client.key")
	if err != nil {
		log.Fatalf("%s: Failed to load client certificate and key: %v", cfg.id, err)
	}

	// Load CA certificate to verify server's certificate
	caCert, err := os.ReadFile("/app/certs/ca.crt")
	if err != nil {
		log.Fatalf("%s: Failed to read CA certificate: %v", cfg.id, err)
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatalf("%s: Failed to append CA certificate to pool.", cfg.id)
	}

	// Configure TLS for the client
	tlsConfig := &tls.Config{
		Certificates:           []tls.Certificate{clientCert},
		RootCAs:                caCertPool,             // Trust server certs signed by this CA
		ServerName:             os.Getenv("SERVER_ID"), // IMPORTANT: Must match the Common Name (CN) in server.crt
		MinVersion:             tls.VersionTLS12,
		KeyLogWriter:           KeylogFile,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}

	// Create gRPC client credentials from TLS config
	creds := credentials.NewTLS(tlsConfig)

	connectAddr := fmt.Sprintf("%s:%s", cfg.connectIP, cfg.connectPort)
	log.Printf("%s: Attempting to connect to peer server at %s with mTLS...", cfg.id, connectAddr)

	// Dial with TLS credentials
	conn, err := grpc.Dial(connectAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("%s: Could not connect to peer server %s: %v", cfg.id, connectAddr, err)
	}
	defer conn.Close()

	client := gossip.NewGossipServiceClient(conn)

	stream, err := client.GossipStream(context.Background())
	if err != nil {
		log.Fatalf("%s: Failed to open gossip stream: %v", cfg.id, err)
	}
	log.Printf("%s: Connected to peer server %s and opened stream with mTLS.", cfg.id, connectAddr)

	go func() {
		msgCount := 0
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stream.Context().Done():
				log.Printf("%s: Client stream context cancelled, stopping sender: %v", cfg.id, stream.Context().Err())
				return
			case <-ticker.C:
				msgCount++
				content := fmt.Sprintf("Greetings from %s (client msg %d)", cfg.id, msgCount)
				err := stream.Send(&gossip.GossipMessage{
					SenderIp:   cfg.id,                   // Assuming cfg.id is the sender's IP
					ReceiverIp: os.Getenv("RECEIVER_IP"), // Set this to the appropriate receiver IP
					Content:    content,
				})
				if err != nil {
					log.Printf("%s: Error sending message to peer stream: %v", cfg.id, err)
					return
				}
				log.Printf("%s: Sent message to peer via client: \"%s\"", cfg.id, content)
			}
		}
	}()

	for {
		req, err := stream.Recv()
		if err == io.EOF {
			log.Printf("%s: Peer closed the send stream (client side).", cfg.id)
			return
		}
		if err != nil {
			log.Printf("%s: Error receiving message from peer stream (client side): %v", cfg.id, err)
			return
		}
		log.Printf("%s: Client received message from %s: \"%s\"", cfg.id, req.GetSenderIp(), req.GetContent())
	}
}

// main function to set up and run the gRPC server and client instances.
// This function now expects specific IP addresses and ports via environment variables.
func main() {
	var wg sync.WaitGroup

	serverID := os.Getenv("SERVER_ID")
	listenIP := os.Getenv("LISTEN_IP") // New: Specific listen IP
	listenPort := os.Getenv("LISTEN_PORT")
	connectIP := os.Getenv("CONNECT_IP") // New: Specific connect IP
	connectPort := os.Getenv("CONNECT_PORT")

	if serverID == "" || listenIP == "" || listenPort == "" || connectIP == "" || connectPort == "" {
		log.Fatalf("Missing environment variables. Please set SERVER_ID, LISTEN_IP, LISTEN_PORT, CONNECT_IP, and CONNECT_PORT.")
	}
	os.Remove("/home/ssl_keys.log")

	KeylogFile, err := os.OpenFile("/home/ssl_keys.log", os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Error opening keylog file : %s", err)
	}

	defer KeylogFile.Close()

	cfg := serverConfig{
		id:          serverID,
		listenIP:    listenIP,
		listenPort:  listenPort,
		connectIP:   connectIP,
		connectPort: connectPort,
	}

	log.Printf("Starting gRPC Server/Client for %s...", cfg.id)

	// Start the server part for this instance
	wg.Add(1)
	go func() {
		startServer(cfg, &wg, KeylogFile)
	}()

	// Start the client part for this instance
	wg.Add(1)
	go func() {
		startClient(cfg, &wg, KeylogFile)
	}()

	log.Printf("%s: Running. Press Ctrl+C to stop.", cfg.id)
	wg.Wait() // Wait indefinitely, as these are long-running services
	select {}
}
