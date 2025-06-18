package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	gossip "grpc_gossip_simulator_fv/gossip"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"google.golang.org/protobuf/proto"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" gossip_parser helper/gossip_parser.c -- -I../headers

// GossipEvent MUST EXACTLY match the 'struct gossip_event' in gossip_parser.c
type GossipEvent struct {
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	MsgType    uint32
	PayloadLen uint32    // This is the total TCP payload length (including HTTP/2 & gRPC framing)
	Payload    [400]byte // Raw captured bytes from TCP payload
}

// These are constants related to HTTP/2 frame header parsing
const (
	http2FrameHeaderLen  = 9 // Length, Type, Flags, Stream ID (3 + 1 + 1 + 4 bytes)
	grpcFramingHeaderLen = 5 // Compression Flag (1 byte) + Message Length (4 bytes)
)

// HTTP2FrameType defines common HTTP/2 frame types
type HTTP2FrameType uint8

const (
	HTTP2FrameData         HTTP2FrameType = 0x0
	HTTP2FrameHeaders      HTTP2FrameType = 0x1
	HTTP2FramePriority     HTTP2FrameType = 0x2
	HTTP2FrameRSTStream    HTTP2FrameType = 0x3
	HTTP2FrameSettings     HTTP2FrameType = 0x4
	HTTP2FramePushPromise  HTTP2FrameType = 0x5
	HTTP2FramePing         HTTP2FrameType = 0x6
	HTTP2FrameGoAway       HTTP2FrameType = 0x7
	HTTP2FrameWindowUpdate HTTP2FrameType = 0x8
	HTTP2FrameContinuation HTTP2FrameType = 0x9
)

func (t HTTP2FrameType) String() string {
	switch t {
	case HTTP2FrameData:
		return "DATA"
	case HTTP2FrameHeaders:
		return "HEADERS"
	case HTTP2FramePriority:
		return "PRIORITY"
	case HTTP2FrameRSTStream:
		return "RST_STREAM"
	case HTTP2FrameSettings:
		return "SETTINGS"
	case HTTP2FramePushPromise:
		return "PUSH_PROMISE"
	case HTTP2FramePing:
		return "PING"
	case HTTP2FrameGoAway:
		return "GOAWAY"
	case HTTP2FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case HTTP2FrameContinuation:
		return "CONTINUATION"
	default:
		return fmt.Sprintf("UNKNOWN_HTTP2_TYPE_0x%x", uint8(t))
	}
}

// gossipMessageTypes now explicitly maps the HTTP/2 frame type numbers to their names.
// This is the correct mapping for `event.MsgType` coming from the C eBPF program.
var gossipMessageTypes = map[uint32]string{
	uint32(HTTP2FrameData):         "DATA",
	uint32(HTTP2FrameHeaders):      "HEADERS",
	uint32(HTTP2FramePriority):     "PRIORITY",
	uint32(HTTP2FrameRSTStream):    "RST_STREAM",
	uint32(HTTP2FrameSettings):     "SETTINGS",
	uint32(HTTP2FramePushPromise):  "PUSH_PROMISE",
	uint32(HTTP2FramePing):         "PING",
	uint32(HTTP2FrameGoAway):       "GOAWAY",
	uint32(HTTP2FrameWindowUpdate): "WINDOW_UPDATE",
	uint32(HTTP2FrameContinuation): "CONTINUATION",
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("EBPF: Failed to remove memlock: %v", err)
	}

	if err := runXDP(); err != nil {
		log.Fatalf("EBPF: XDP failed to start: %v", err)
	}
}

func runXDP() error {
	spec, err := loadGossip_parser()
	if err != nil {
		return fmt.Errorf("EBPF: Failed to load eBPF program spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("EBPF: Failed to create eBPF collection: %w", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs["capture_hlf_gossip"]
	if !ok {
		return fmt.Errorf("EBPF: BPF program 'capture_hlf_gossip' not found in collection")
	}

	ifname := "eth0" // Monitoring loopback interface

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("EBPF: Failed to get interface %s: %v", ifname, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("EBPF: Failed to attach XDP program to %s: %w", ifname, err)
	}
	defer l.Close()

	log.Printf("EBPF: Successfully attached XDP program to interface %s (index %d).", ifname, iface.Index)

	return runEventLoop(coll.Maps["gossip_events"])
}

func runEventLoop(eventMap *ebpf.Map) error {
	rd, err := perf.NewReader(eventMap, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("EBPF: Failed to create perf reader: %w", err)
	}
	defer rd.Close()

	fmt.Println("EBPF: Monitoring HLF gossip messages on loopback interface...")
	fmt.Println("EBPF: Press Ctrl+C to stop")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	stats := make(map[uint32]int64)
	go func() {
		<-sig
		fmt.Println("\nEBPF: Shutting down eBPF monitor...")
		printStats(stats)
		os.Exit(0)
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == perf.ErrClosed {
				break
			}
			log.Printf("EBPF: Error reading perf event: %v", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("EBPF: Lost %d samples", record.LostSamples)
			continue
		}

		fmt.Printf("\n")
		fmt.Print(record.RawSample)
		fmt.Printf("\n")

		event := parseEvent(record.RawSample)
		if event != nil {
			processEvent(event, stats)
		}
	}
	return nil
}

func parseEvent(data []byte) *GossipEvent {
	const expectedSize = 428 // Total size of C struct: 4*7 + 128 = 28 + 400 = 428 bytes
	if len(data) < expectedSize {
		log.Printf("EBPF: Received short event data: %d bytes, expected %d", len(data), expectedSize)
		return nil
	}

	event := &GossipEvent{}
	reader := bytes.NewReader(data)

	if err := binary.Read(reader, binary.LittleEndian, &event.SrcIP); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.DstIP); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.SrcPort); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.DstPort); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.Seq); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.Ack); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.MsgType); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.PayloadLen); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &event.Payload); err != nil {
		return nil
	}

	return event
}

// processEvent formats, deserializes, and prints the captured gossip event.
func processEvent(event *GossipEvent, stats map[uint32]int64) {
	stats[event.MsgType]++
	msgTypeName, exists := gossipMessageTypes[event.MsgType]
	if !exists {
		msgTypeName = HTTP2FrameType(event.MsgType).String()
	}

	srcIP := intToIP(event.SrcIP)
	dstIP := intToIP(event.DstIP)

	var payloadDisplay string
	actualTCPPayloadBytes := event.Payload[:] // This is the raw buffer copied from eBPF

	// Trim the actualTCPPayloadBytes to the length reported by eBPF (PayloadLen)
	if int(event.PayloadLen) > len(actualTCPPayloadBytes) {
		log.Printf("EBPF: WARNING: Captured buffer (%d bytes) is smaller than reported TCP payload length (%d bytes). Processing truncated data.", len(actualTCPPayloadBytes), event.PayloadLen)
	} else {
		actualTCPPayloadBytes = actualTCPPayloadBytes[:event.PayloadLen] // Trim to actual length
	}

	log.Printf("EBPF Debug: Total TCP Payload (len %d): %x", len(actualTCPPayloadBytes), actualTCPPayloadBytes)

	// --- Step 1: Parse HTTP/2 Frame Header ---
	if len(actualTCPPayloadBytes) < http2FrameHeaderLen {
		payloadDisplay = fmt.Sprintf("Too short for HTTP/2 framing (len %d): %x", len(actualTCPPayloadBytes), actualTCPPayloadBytes)
		log.Printf("EBPF Debug: %s", payloadDisplay)
	}

	http2FrameBytes := actualTCPPayloadBytes[:http2FrameHeaderLen]
	http2FramePayload := actualTCPPayloadBytes[http2FrameHeaderLen:]

	fmt.Printf("\n")
	fmt.Print(http2FrameBytes)
	fmt.Printf("\n")

	fmt.Printf("\n")
	fmt.Print(http2FramePayload)
	fmt.Printf("\n")

	// HTTP/2 Frame Header (9 bytes):
	// Length (3 bytes, MSB is reserved) - Big Endian
	// Type (1 byte)
	// Flags (1 byte)
	// R (1 bit) + Stream ID (31 bits) - Big Endian
	// Read Length (3 bytes) - need to convert to uint32
	http2FrameLength := binary.BigEndian.Uint32(append([]byte{0x00}, http2FrameBytes[0:3]...)) // Prepend 0x00 for 3-byte length
	http2FrameType := HTTP2FrameType(http2FrameBytes[3])
	http2FrameFlags := http2FrameBytes[4]
	http2StreamID := binary.BigEndian.Uint32(http2FrameBytes[5:9]) & 0x7FFFFFFF // Mask out reserved bit

	log.Printf("EBPF Debug: HTTP/2 Frame -> Len: %d, Type: %s (0x%x), Flags: 0x%x, StreamID: %d",
		http2FrameLength, http2FrameType, uint8(http2FrameType), http2FrameFlags, http2StreamID)
	// Crucial check: Does the http2FrameLength match the actual payload size?
	// If it's a DATA frame, its length should correspond to the gRPC payload + framing
	if http2FrameType == HTTP2FrameData && http2FrameLength > uint32(len(http2FramePayload)) {
		payloadDisplay = fmt.Sprintf("HTTP/2 DATA frame reported length (%d) exceeds captured frame payload (%d)", http2FrameLength, len(http2FramePayload))
		log.Printf("EBPF Debug: %s", payloadDisplay)
		goto printEvent // Data is truncated or malformed
	}

	// --- Step 2: Parse gRPC Framing (ONLY if it's an HTTP/2 DATA frame) ---
	if http2FrameType == HTTP2FrameData {
		grpcDataPayload := http2FramePayload // The HTTP/2 DATA frame's payload is the gRPC payload

		if len(grpcDataPayload) < grpcFramingHeaderLen {
			payloadDisplay = fmt.Sprintf("HTTP/2 DATA frame payload too short for gRPC framing (len %d): %x", len(grpcDataPayload), grpcDataPayload)
			log.Printf("EBPF Debug: %s", payloadDisplay)
			goto printEvent // Skip further processing if too short
		}

		compressionFlag := grpcDataPayload[0]
		// Correctly extract the 4-byte length field. Slice is [start:end], so [1:5] gets bytes at index 1, 2, 3, 4.
		protobufMsgLen := binary.BigEndian.Uint32(grpcDataPayload[1:grpcFramingHeaderLen])

		// The actual protobuf message bytes start after the 5-byte header
		protoPayloadStart := grpcFramingHeaderLen
		protoPayloadEnd := protoPayloadStart + int(protobufMsgLen)

		log.Printf("EBPF Debug: gRPC Frame -> Compression: 0x%x, Reported Proto Len: %d, Proto Start: %d, Proto End (expected): %d",
			compressionFlag, protobufMsgLen, protoPayloadStart, protoPayloadEnd)

		if compressionFlag == 0x00 && protoPayloadEnd <= len(grpcDataPayload) {
			// It's uncompressed (0x00), and the reported protobuf message length fits within the captured bytes
			protoPayloadBytes := grpcDataPayload[protoPayloadStart:protoPayloadEnd]
			log.Printf("EBPF Debug: Attempting Unmarshal on protoPayloadBytes (len %d): %x",
				len(protoPayloadBytes), protoPayloadBytes)

			var grpcMsg gossip.GossipMessage // Use the imported protobuf message type
			if err := proto.Unmarshal(protoPayloadBytes, &grpcMsg); err == nil {
				payloadDisplay = fmt.Sprintf("Protobuf Msg: SenderID='%s', Content='%s'", grpcMsg.GetSenderId(), grpcMsg.GetContent())
			} else {
				payloadDisplay = fmt.Sprintf("Unmarshal Error: %v | ProtoPayload (len %d): %x | Full gRPC Data Payload (len %d): %x",
					err, len(protoPayloadBytes), protoPayloadBytes, len(grpcDataPayload), grpcDataPayload)
				log.Printf("EBPF Debug: %s", payloadDisplay)
			}
		} else {
			// Either compressed (not 0x00) or the reported protobufMsgLen doesn't fit
			payloadDisplay = fmt.Sprintf("gRPC Framing Issue (Flag: 0x%x, ReportedLen: %d, ActualgRPCDataLen: %d): %x",
				compressionFlag, protobufMsgLen, len(grpcDataPayload), grpcDataPayload)
			log.Printf("EBPF Debug: %s", payloadDisplay)
		}
	} else {
		// Not a DATA frame, so it doesn't contain a gRPC message body.
		payloadDisplay = fmt.Sprintf("HTTP/2 %s Frame (Flags: 0x%x, StreamID: %d) - No gRPC Body",
			http2FrameType, http2FrameFlags, http2StreamID)
		if len(http2FramePayload) > 0 {
			payloadDisplay += fmt.Sprintf(" | Payload: %x", http2FramePayload)
		}
		log.Printf("EBPF Debug: %s", payloadDisplay)
	}

printEvent: // Label for goto statements
	fmt.Printf("EBPF [%s] %s:%d -> %s:%d | Seq:%d Ack:%d | Type: %s | Len: %d | Payload: %s\n",
		time.Now().Format("15:04:05.000"),
		srcIP, event.SrcPort,
		dstIP, event.DstPort,
		event.Seq, event.Ack,
		msgTypeName,
		event.PayloadLen, // This is still the full TCP payload length from eBPF
		payloadDisplay)
	fmt.Print("\n")
}

func printStats(stats map[uint32]int64) {
	fmt.Println("\nEBPF == Message Statistics ==")
	for msgType, count := range stats {
		msgTypeName := gossipMessageTypes[msgType]
		if msgTypeName == "" {
			msgTypeName = fmt.Sprintf("UNKNOWN_HTTP/2_TYPE_0x%x", msgType)
		}
		fmt.Printf("EBPF %s: %d\n", msgTypeName, count)
	}
}

func intToIP(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}
