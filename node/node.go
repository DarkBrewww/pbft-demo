package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	//"encoding/asn1" // For invalid signature attack
	"encoding/gob"
	"fmt"
	"log"

	//"math/big" // For invalid signature attack
	"regexp"
	"sort"    // Import for sorting log keys
	"strconv" // For converting string to int in dark attack parsing
	"strings" // For parsing in-dark attack
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	pb "bft-DarkBrewww/proto" // CORRECTED IMPORT
)

// Define node states
type NodeState string

const (
	StateNormal       NodeState = "Normal"
	StateViewChanging NodeState = "ViewChanging"

	// Request timer duration
	RequestTimeout = 5 * time.Second
)

// Define log entry statuses
const (
	StatusNone        = ""
	StatusPrePrepared = "pre-prepared"
	StatusPrepared    = "prepared"
	StatusCommitted   = "committed-local"
	StatusExecuted    = "executed"
)

// Internal representation of a log entry for a specific request
type InternalLogEntry struct {
	SequenceNumber int64
	View           int32
	Digest         []byte
	Request        *pb.ClientRequest // Store the full request
	Status         string            // e.g., "pre-prepared", "prepared", "committed", "executed"

	// Proofs needed for PBFT state transfer and linear commit
	PrePrepareMsg *pb.PrePrepareRequest      // The message that started it all for this node
	PrepareVotes  map[int]*pb.PrepareRequest // replicaID -> PrepareMsg (received by primary or backup)
	CommitVotes   map[int]*pb.CommitRequest  // replicaID -> CommitMsg (received by primary or backup)
	FullPrepareRx bool                       // Flag if FullPrepare was received by backup
	FullCommitRx  bool                       // Flag if FullCommit was received by backup
}

// Node struct holds the state for a single PBFT replica
type Node struct {
	pb.UnimplementedPbftNodeServer

	ID           int
	NodeAddrs    map[int]string
	F            int
	N            int
	QuorumSize   int // 2f+1
	ClientQuorum int // f+1

	// --- ATTACK FIELDS ---
	AttackModes         map[string]bool // Stores "none", "crash", "sign", "equivocation", "time", "dark"
	darkTargets         map[int]bool    // Parsed set of targets for 'dark'
	equivocationTargets map[int]bool    // Parsed set of targets for 'equivocation'
	State               NodeState
	View                int32
	SeqNum              int64                     // Next sequence number to assign by primary
	LastExecuted        int64                     // Last sequence number *successfully executed*
	Watermarks          struct{ Low, High int64 } // Checkpoint watermarks

	MessageLog map[int64]*InternalLogEntry // seqNum -> LogEntry (using internal struct)

	DB map[string]int32

	PrivateKey *ecdsa.PrivateKey
	PublicKeys map[int]*ecdsa.PublicKey // id -> key

	mu          sync.Mutex
	grpcClients map[int]pb.PbftNodeClient
	clientConn  map[int]*grpc.ClientConn

	// Map to store channels for pending client replies
	pendingClientReplies map[string]chan *pb.ClientReply // key (client-timestamp) -> channel

	// --- VIEW CHANGE FIELDS ---
	// Stores received view change messages
	// key = newView, value = map[replicaID] -> message
	viewChangeVotes map[int32]map[int]*pb.ViewChangeRequest

	// Timers
	requestTimers map[int64]*time.Timer // seqNum -> Timer
	// viewTimer     *time.Timer // TODO: Add a timer for the view change process itself
}

// NewNode creates and initializes a new PBFT node
// Now accepts attackType
// *** MODIFIED: Accepts the new attackString ***
func NewNode(id int, addrs map[int]string, f int, privKey *ecdsa.PrivateKey, pubKeys map[int]*ecdsa.PublicKey, attackString string) (*Node, error) {
	n := len(addrs)
	if n < (3*f + 1) {
		return nil, fmt.Errorf("insufficient nodes (%d) for f=%d", n, f)
	}
	if id < 0 || id >= n {
		return nil, fmt.Errorf("node ID %d out of range (0-%d)", id, n-1)
	}

	// --- Parse Attack Mode ---
	attackModes := make(map[string]bool)
	darkTargets := make(map[int]bool)
	equivocationTargets := make(map[int]bool)
	re := regexp.MustCompile(`n(\d+)`) // Regex to find node numbers like n1, n6, etc.

	attacks := strings.Split(attackString, ";")
	for _, attack := range attacks {
		attack = strings.TrimSpace(attack)
		if attack == "" || attack == "none" {
			continue
		}

		switch {
		case strings.HasPrefix(attack, "dark"):
			attackModes["dark"] = true
			if open := strings.Index(attack, "("); open != -1 {
				if close := strings.Index(attack, ")"); close > open {
					params := attack[open : close+1]
					matches := re.FindAllStringSubmatch(params, -1)
					for _, match := range matches {
						targetID, _ := strconv.Atoi(match[1])
						darkTargets[targetID-1] = true // 1-based in CSV to 0-based internal
					}
				}
			}

		case strings.HasPrefix(attack, "equivocation"):
			attackModes["equivocation"] = true
			if open := strings.Index(attack, "("); open != -1 {
				if close := strings.Index(attack, ")"); close > open {
					params := attack[open : close+1]
					matches := re.FindAllStringSubmatch(params, -1)
					for _, match := range matches {
						targetID, _ := strconv.Atoi(match[1])
						equivocationTargets[targetID-1] = true // 1-based in CSV to 0-based internal
					}
				}
			}

		case strings.HasPrefix(attack, "time"):
			attackModes["time"] = true

		case strings.HasPrefix(attack, "sign"):
			attackModes["sign"] = true

		case strings.HasPrefix(attack, "crash"):
			attackModes["crash"] = true
		}
	}
	// --- End Parse Attack Mode ---

	node := &Node{
		ID:                   id,
		NodeAddrs:            addrs,
		F:                    f,
		N:                    n,
		QuorumSize:           2*f + 1,
		ClientQuorum:         f + 1,
		AttackModes:          attackModes, // *** MODIFIED ***
		darkTargets:          darkTargets,
		equivocationTargets:  equivocationTargets,
		State:                StateNormal,
		View:                 0,
		SeqNum:               0,
		LastExecuted:         0,
		Watermarks:           struct{ Low, High int64 }{0, 1000},
		MessageLog:           make(map[int64]*InternalLogEntry),
		DB:                   make(map[string]int32),
		PrivateKey:           privKey,
		PublicKeys:           pubKeys,
		grpcClients:          make(map[int]pb.PbftNodeClient),
		clientConn:           make(map[int]*grpc.ClientConn),
		pendingClientReplies: make(map[string]chan *pb.ClientReply),
		requestTimers:        make(map[int64]*time.Timer),
		viewChangeVotes:      make(map[int32]map[int]*pb.ViewChangeRequest),
	}

	for _, client := range []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"} {
		node.DB[client] = 10
	}

	log.Printf("Node %d initialized. N=%d, f=%d, Quorum=%d, ATTACK_MODES: %v, DARK_TARGETS: %v, EQUIV_TARGETS: %v", id, n, f, node.QuorumSize, node.AttackModes, node.darkTargets, node.equivocationTargets)
	return node, nil
}

// getGrpcClient establishes or retrieves a gRPC client connection
func (n *Node) getGrpcClient(peerID int) (pb.PbftNodeClient, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if client, ok := n.grpcClients[peerID]; ok {
		return client, nil
	}
	peerAddr, ok := n.NodeAddrs[peerID]
	if !ok {
		return nil, fmt.Errorf("unknown peer ID %d", peerID)
	}

	conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer %d at %s: %w", peerID, peerAddr, err)
	}

	client := pb.NewPbftNodeClient(conn)
	n.grpcClients[peerID] = client
	n.clientConn[peerID] = conn
	log.Printf("Node %d established gRPC connection to Node %d at %s", n.ID, peerID, peerAddr)
	return client, nil
}

// CloseConnections cleans up gRPC client connections
func (n *Node) CloseConnections() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, conn := range n.clientConn {
		log.Printf("Node %d closing connection to Node %d", n.ID, id)
		conn.Close()
	}
}

// --- Cryptographic Functions ---
// In node.go

// sign creates a signature for the core part of a message
func (n *Node) sign(data []byte) (*pb.Signature, error) {
	if n.PrivateKey == nil {
		return nil, fmt.Errorf("private key not initialized for node %d", n.ID)
	}

	// --- Attack Logic: Invalid Signature ---
	// *** MODIFIED ***
	if n.AttackModes["sign"] {
		log.Printf("Node %d [ATTACK]: Generating INVALID signature", n.ID)

		// Create a normal, valid signature first
		hash := sha256.Sum256(data)
		sigBytes, err := ecdsa.SignASN1(rand.Reader, n.PrivateKey, hash[:])
		if err != nil {
			return nil, fmt.Errorf("failed to sign data: %w", err)
		}

		// *** THIS IS THE FIX ***
		// Corrupt the signature by flipping the last byte.
		// This is guaranteed to make it invalid.
		if len(sigBytes) > 0 {
			sigBytes[len(sigBytes)-1] = ^sigBytes[len(sigBytes)-1] // Flip all bits of the last byte
		}

		return &pb.Signature{
			SignerIdBytes: []byte(fmt.Sprintf("%d", n.ID)),
			Value:         sigBytes,
		}, nil
	}
	// --- End Attack Logic ---

	// --- Normal Logic ---
	hash := sha256.Sum256(data)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, n.PrivateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	return &pb.Signature{
		SignerIdBytes: []byte(fmt.Sprintf("%d", n.ID)),
		Value:         sigBytes,
	}, nil
}

// verify checks a signature against the known public key of the signer
func (n *Node) verify(signerID int, data []byte, signature *pb.Signature) bool {
	if signature == nil {
		log.Printf("Node %d: Verification failed - signature is nil", n.ID)
		return false
	}
	pubKey, ok := n.PublicKeys[signerID]
	if !ok {
		log.Printf("Node %d: Verification failed - no public key for signer %d", n.ID, signerID)
		return false
	}
	hash := sha256.Sum256(data)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature.Value)
	if !valid {
		log.Printf("Node %d: Verification FAILED for message signed by %d", n.ID, signerID)
	}
	return valid
}

// digest computes a SHA256 hash of the client request using deterministic marshalling
func digest(m *pb.ClientRequest) ([]byte, error) {
	reqBytes, err := proto.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request for digest: %w", err)
	}
	hash := sha256.Sum256(reqBytes)
	return hash[:], nil
}

// --- Helper Functions for Signing Data ---

// prePrepareDataForSig serializes the core PrePrepare fields for signing/verification
func prePrepareDataForSig(v int32, n int64, d []byte) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// prepareDataForSig serializes the core Prepare fields for signing/verification
func prepareDataForSig(v int32, n int64, d []byte, i int32) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	if err := enc.Encode(i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// commitDataForSig serializes the core Commit fields for signing/verification
func commitDataForSig(v int32, n int64, d []byte, i int32) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	if err := enc.Encode(i); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// clientReplyDataForSig serializes the core ClientReply fields for signing/verification
func clientReplyDataForSig(v int32, t int64, c string, i int32, r string) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Encode(t); err != nil {
		return nil, err
	}
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	if err := enc.Encode(i); err != nil {
		return nil, err
	}
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- Implement gRPC Service Methods ---

// getPrimaryID calculates the primary for a given view
func (n *Node) getPrimaryID(view int32) int {
	return int(view) % n.N
}

// SubmitRequest is called by clients.
// Implements "Equivocation", "Timing", and Read-Only logic
func (n *Node) SubmitRequest(ctx context.Context, req *pb.ClientRequest) (*pb.ClientReply, error) {
	// --- Read-Only Optimistic Path ---
	tx := req.Transaction
	if tx != nil && tx.Receiver == "" && tx.Amount == 0 {
		n.mu.Lock()
		log.Printf("Node %d received Read-Only request from %s (ts=%d). Executing immediately.", n.ID, req.ClientId, req.Timestamp)

		// Execute immediately against the local state.
		result := ""
		if val, ok := n.DB[tx.Sender]; ok {
			result = fmt.Sprintf("Balance: %d", val)
		} else {
			n.DB[tx.Sender] = 10
			result = "Balance: 10"
		}

		view := n.View
		n.mu.Unlock() // Unlock before signing

		// Create and sign the reply.
		replyCoreData, err := clientReplyDataForSig(view, req.Timestamp, req.ClientId, int32(n.ID), result)
		if err != nil {
			log.Printf("Node %d: Failed to serialize read-only reply for signing: %v", n.ID, err)
			return &pb.ClientReply{Result: "failed: internal error"}, nil
		}
		signature, err := n.sign(replyCoreData)
		if err != nil {
			log.Printf("Node %d: Failed to sign read-only reply: %v", n.ID, err)
			return &pb.ClientReply{Result: "failed: internal error"}, nil
		}

		log.Printf("Node %d sending immediate reply for read-only request to %s.", n.ID, req.ClientId)
		return &pb.ClientReply{
			View:      view,
			Timestamp: req.Timestamp,
			ClientId:  req.ClientId,
			ReplicaId: int32(n.ID),
			Result:    result,
			Signature: signature,
		}, nil
	}
	// --- End Read-Only Path ---

	// --- Normal Read-Write Path ---
	n.mu.Lock()
	log.Printf("Node %d received Read-Write request from client %s (ts=%d)", n.ID, req.ClientId, req.Timestamp)

	isPrimary := n.getPrimaryID(n.View) == n.ID
	currentView := n.View

	// Key for this specific client request
	reqKey := fmt.Sprintf("%s-%d", req.ClientId, req.Timestamp)

	// Check if this request is already being processed
	replyChan, ok := n.pendingClientReplies[reqKey]
	if !ok {
		// --- This is a new request ---
		replyChan = make(chan *pb.ClientReply, 1)
		n.pendingClientReplies[reqKey] = replyChan

		if isPrimary {
			// --- Primary Logic ---

			// --- Attack Logic: Timing ---
			if n.AttackModes["time"] {
				log.Printf("Node %d (Primary) [ATTACK]: Timing attack. Delaying for 500ms...", n.ID)
				n.mu.Unlock() // Unlock while sleeping
				time.Sleep(500 * time.Millisecond)
				n.mu.Lock() // Re-lock
			}
			// --- End Attack Logic ---

			n.SeqNum++
			seqNum := n.SeqNum

			d, err := digest(req)
			if err != nil {
				n.mu.Unlock()
				log.Printf("Node %d (Primary): Failed to calculate digest: %v", n.ID, err)
				return &pb.ClientReply{Result: "failed: internal error"}, nil
			}
			digestProto := &pb.Digest{Hash: d}

			// --- Attack Logic: Equivocation ---
			if n.AttackModes["equivocation"] {
				log.Printf("Node %d (Primary) [ATTACK]: Executing Equivocation for seq %d", n.ID, seqNum)

				// Log the "official" request as seqNum
				n.MessageLog[seqNum] = &InternalLogEntry{
					SequenceNumber: seqNum,
					View:           currentView,
					Digest:         d,
					Request:        req,
					Status:         StatusPrePrepared, // Tentative
					PrepareVotes:   make(map[int]*pb.PrepareRequest),
					CommitVotes:    make(map[int]*pb.CommitRequest),
				}

				// Burn the next sequence number
				n.SeqNum++
				equivSeqNum := n.SeqNum

				// Log the *conflicting* request
				n.MessageLog[equivSeqNum] = &InternalLogEntry{
					SequenceNumber: equivSeqNum,
					View:           currentView,
					Digest:         d,
					Request:        req, // Same request, different seq
					Status:         StatusPrePrepared,
					PrepareVotes:   make(map[int]*pb.PrepareRequest),
					CommitVotes:    make(map[int]*pb.CommitRequest),
				}

				// Create PrePrepare for (seq, req)
				prePrepareMsg1, _ := n.createSignedPrePrepare(currentView, seqNum, d, req)
				// Create PrePrepare for (seq+1, req)
				prePrepareMsg2, _ := n.createSignedPrePrepare(currentView, equivSeqNum, d, req)
				n.logPrePrepare(prePrepareMsg1)
				n.logPrePrepare(prePrepareMsg2)

				n.mu.Unlock() // Unlock before broadcasting

				// Send conflicting messages
				log.Printf("Node %d [ATTACK]: Sending conflicting messages to targets %v", n.ID, n.equivocationTargets)
				for peerID := range n.NodeAddrs {
					if peerID == n.ID {
						continue
					}

					var msgToSend *pb.PrePrepareRequest

					// *** THIS IS THE FIX ***
					// It checks if the peerID is in the map we created.
					if n.equivocationTargets[peerID] {
						// peerID is in the equivocation target set: Send the conflicting message
						msgToSend = prePrepareMsg2
					} else {
						// peerID is not targeted for equivocation: Send the normal message
						msgToSend = prePrepareMsg1
					}

					go n.sendToPeer(peerID, msgToSend, "PrePrepare")
				}
				log.Printf("Node %d [ATTACK]: Sent seq %d to even nodes and seq %d to odd nodes", n.ID, seqNum, equivSeqNum)

			} else {
				// --- Normal Primary Logic ---
				prePrepareCoreData, err := prePrepareDataForSig(currentView, seqNum, d)
				if err != nil {
					n.mu.Unlock()
					log.Printf("Node %d (Primary): Failed to serialize PrePrepare for signing: %v", n.ID, err)
					return &pb.ClientReply{Result: "failed: internal error"}, nil
				}
				signature, err := n.sign(prePrepareCoreData)
				if err != nil {
					n.mu.Unlock()
					log.Printf("Node %d (Primary): Failed to sign PrePrepare: %v", n.ID, err)
					return &pb.ClientReply{Result: "failed: internal error"}, nil
				}

				prePrepareMsg := &pb.PrePrepareRequest{
					View:           currentView,
					SequenceNumber: seqNum,
					Digest:         digestProto,
					Request:        req,
					Signature:      signature,
				}

				n.MessageLog[seqNum] = &InternalLogEntry{
					SequenceNumber: seqNum,
					View:           currentView,
					Digest:         d,
					Request:        req,
					Status:         StatusPrePrepared,
					PrePrepareMsg:  prePrepareMsg,
					PrepareVotes:   make(map[int]*pb.PrepareRequest),
					CommitVotes:    make(map[int]*pb.CommitRequest),
				}
				log.Printf("Node %d (Primary) assigned seq=%d to request %s", n.ID, seqNum, reqKey)

				n.mu.Unlock()

				// Broadcast PrePrepare to all backups
				for peerID := range n.NodeAddrs {
					if peerID == n.ID {
						continue
					}
					// Use the generic send helper which checks for In-dark
					go n.sendToPeer(peerID, prePrepareMsg, "PrePrepare")
				}
			} // --- End Attack/Normal Logic ---

		} else {
			// --- Backup Logic ---
			// NO FORWARDING. Just log and wait for consensus.
			log.Printf("Node %d (Backup) received %s. Awaiting consensus.", n.ID, reqKey)
			n.mu.Unlock()
		}
	} else {
		// --- This is a re-transmitted request ---
		log.Printf("Node %d received duplicate SubmitRequest for %s. Waiting on existing channel.", n.ID, reqKey)
		n.mu.Unlock()
	}

	// --- Wait for Reply ---
	// Both Primary and Backup goroutines will wait here.
	select {
	case reply := <-replyChan:
		log.Printf("Node %d sending final reply for %s: %s", n.ID, reqKey, reply.Result)
		n.mu.Lock()
		delete(n.pendingClientReplies, reqKey)
		n.mu.Unlock()
		return reply, nil

	case <-ctx.Done(): // Client cancelled or timed out
		log.Printf("Node %d: Client request context done for %s", n.ID, reqKey)
		n.mu.Lock()
		delete(n.pendingClientReplies, reqKey)
		n.mu.Unlock()
		return &pb.ClientReply{Result: "failed: client timeout"}, nil

	case <-time.After(10 * time.Second): // Our own internal timeout
		log.Printf("Node %d: Internal timeout for %s", n.ID, reqKey)
		n.mu.Lock()
		delete(n.pendingClientReplies, reqKey)
		n.mu.Unlock()
		return &pb.ClientReply{Result: "failed: node timeout"}, nil
	}
}

// createSignedPrePrepare is a helper for the equivocation attack
func (n *Node) createSignedPrePrepare(v int32, seq int64, d []byte, req *pb.ClientRequest) (*pb.PrePrepareRequest, error) {
	prePrepareCoreData, err := prePrepareDataForSig(v, seq, d)
	if err != nil {
		return nil, err
	}
	signature, err := n.sign(prePrepareCoreData) // Will use malicious sign if node is in "sign" mode
	if err != nil {
		return nil, err
	}

	return &pb.PrePrepareRequest{
		View:           v,
		SequenceNumber: seq,
		Digest:         &pb.Digest{Hash: d},
		Request:        req,
		Signature:      signature,
	}, nil
}

// sendToPeer handles sending any message to a peer, checking for "In-dark" attack
func (n *Node) sendToPeer(peerID int, msg interface{}, msgType string) {
	// --- Attack Logic: In-dark ---
	// Check if the target peerID is in our "dark" list
	if n.AttackModes["dark"] && n.darkTargets[peerID] {
		log.Printf("Node %d [ATTACK]: In-dark attack. *NOT* sending %s to target Node %d.", n.ID, msgType, peerID)
		return // Silently drop the message
	}
	// --- End Attack Logic ---

	// --- Normal Logic ---
	client, err := n.getGrpcClient(peerID)
	if err != nil {
		log.Printf("Node %d: Failed to get client for %s to %d: %v", n.ID, msgType, peerID, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var rpcErr error
	switch m := msg.(type) {
	case *pb.PrePrepareRequest:
		_, rpcErr = client.SendPrePrepare(ctx, m)
	case *pb.PrepareRequest:
		_, rpcErr = client.SendPrepare(ctx, m)
	case *pb.FullPrepareRequest:
		_, rpcErr = client.SendFullPrepare(ctx, m)
	case *pb.CommitRequest:
		_, rpcErr = client.SendCommit(ctx, m)
	case *pb.FullCommitRequest:
		_, rpcErr = client.SendFullCommit(ctx, m)
	case *pb.ViewChangeRequest:
		_, rpcErr = client.SendViewChange(ctx, m)
	case *pb.NewViewRequest:
		_, rpcErr = client.SendNewView(ctx, m)
	default:
		log.Printf("Node %d: Unknown message type in sendToPeer: %T", n.ID, msg)
		return
	}

	if rpcErr != nil {
		log.Printf("Node %d: Failed to send %s to %d: %v", n.ID, msgType, peerID, rpcErr)
	}
}

// SendPrePrepare is called by the primary, handled by backups.
// Implements "Crash" attack and starts request timer
func (n *Node) SendPrePrepare(ctx context.Context, req *pb.PrePrepareRequest) (*pb.Ack, error) {

	// --- Attack Logic: Crash (as Backup) ---
	// As per PDF: (a) fails to send any prepare messages
	if n.AttackModes["crash"] {
		log.Printf("Node %d (Backup) [ATTACK]: Crashing. Received PrePrepare for seq %d but will not send Prepare.", n.ID, req.SequenceNumber)
		n.mu.Lock()
		defer n.mu.Unlock()

		// We should still validate it so we can log it
		primaryID := n.getPrimaryID(req.View)
		prePrepareCoreData, _ := prePrepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash)
		if !n.verify(primaryID, prePrepareCoreData, req.Signature) {
			return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
		}
		d, err := digest(req.Request)
		if err != nil || !bytes.Equal(d, req.Digest.Hash) {
			return &pb.Ack{Success: false, ErrorMessage: "digest mismatch"}, nil
		}

		// Log it but don't send Prepare
		n.MessageLog[req.SequenceNumber] = &InternalLogEntry{
			SequenceNumber: req.SequenceNumber,
			View:           req.View,
			Digest:         req.Digest.Hash,
			Request:        req.Request,
			Status:         StatusPrePrepared, // Log it as pre-prepared
			PrePrepareMsg:  req,
			PrepareVotes:   make(map[int]*pb.PrepareRequest),
			CommitVotes:    make(map[int]*pb.CommitRequest),
		}
		log.Printf("Node %d (Backup) [ATTACK]: Logged PrePrepare seq=%d but will NOT send Prepare.", n.ID, req.SequenceNumber)
		return &pb.Ack{Success: true}, nil // Lie and say we're fine
	}
	// --- End Attack Logic ---

	// --- Normal Logic ---
	n.mu.Lock()
	log.Printf("Node %d received PrePrepare from primary for seq=%d view=%d", n.ID, req.SequenceNumber, req.View)

	primaryID := n.getPrimaryID(req.View)
	prePrepareCoreData, err := prePrepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash)
	if err != nil {
		n.mu.Unlock()
		log.Printf("Node %d: Failed to serialize PrePrepare for verification: %v", n.ID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal error"}, nil
	}

	if !n.verify(primaryID, prePrepareCoreData, req.Signature) {
		log.Printf("Node %d: Invalid signature on PrePrepare from node %d", n.ID, primaryID)
		n.mu.Unlock()
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}

	// --- Check if we're in a view change ---
	if n.State == StateViewChanging && req.View < n.View {
		log.Printf("Node %d: In ViewChanging state, ignoring old PrePrepare for view %d", n.ID, req.View)
		n.mu.Unlock()
		return &pb.Ack{Success: false, ErrorMessage: "node in view change"}, nil
	}

	if req.View < n.View {
		log.Printf("Node %d: Received PrePrepare for old view %d (current %d)", n.ID, req.View, n.View)
		n.mu.Unlock()
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	if req.SequenceNumber <= n.Watermarks.Low || req.SequenceNumber > n.Watermarks.High {
		log.Printf("Node %d: PrePrepare seq num %d outside watermarks [%d, %d]", n.ID, req.SequenceNumber, n.Watermarks.Low, n.Watermarks.High)
		n.mu.Unlock()
		return &pb.Ack{Success: false, ErrorMessage: "sequence number out of bounds"}, nil
	}

	existingEntry, ok := n.MessageLog[req.SequenceNumber]
	if ok && existingEntry.View == req.View && !bytes.Equal(existingEntry.Digest, req.Digest.Hash) {
		log.Printf("Node %d: Conflicting PrePrepare for seq %d view %d!", n.ID, req.SequenceNumber, req.View)

		// This is an equivocation attack by the primary! Trigger a view change.
		log.Printf("Node %d: Equivocation detected! Triggering view change.", n.ID)
		n.startViewChange() // We need to hold the lock for this

		// n.mu.Unlock() // startViewChange now unlocks/relocks
		return &pb.Ack{Success: false, ErrorMessage: "conflicting digest for same seq/view"}, nil
	}

	d, err := digest(req.Request)
	if err != nil || !bytes.Equal(d, req.Digest.Hash) {
		log.Printf("Node %d: Digest mismatch for PrePrepare seq %d view %d!", n.ID, req.SequenceNumber, req.View)
		n.mu.Unlock()
		return &pb.Ack{Success: false, ErrorMessage: "digest mismatch"}, nil
	}

	if !ok || existingEntry.View < req.View {
		n.MessageLog[req.SequenceNumber] = &InternalLogEntry{
			SequenceNumber: req.SequenceNumber,
			View:           req.View,
			Digest:         req.Digest.Hash,
			Request:        req.Request,
			Status:         StatusPrePrepared,
			PrePrepareMsg:  req,
			PrepareVotes:   make(map[int]*pb.PrepareRequest),
			CommitVotes:    make(map[int]*pb.CommitRequest),
		}
	} else {
		existingEntry.Status = StatusPrePrepared
		existingEntry.PrePrepareMsg = req
	}

	log.Printf("Node %d PrePrepared seq=%d view=%d", n.ID, req.SequenceNumber, req.View)

	// --- START REQUEST TIMER ---
	// As a backup, if we get a PrePrepare, we start a timer.
	if timer, ok := n.requestTimers[req.SequenceNumber]; ok {
		timer.Stop() // Stop and delete any existing timer for this seq
	}
	n.requestTimers[req.SequenceNumber] = time.AfterFunc(RequestTimeout, func() {
		n.handleRequestTimeout(req.SequenceNumber, req.View)
	})
	log.Printf("Node %d (Backup) started timer for seq %d", n.ID, req.SequenceNumber)
	// --- END TIMER LOGIC ---

	prepareCoreData, err := prepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash, int32(n.ID))
	if err != nil {
		n.mu.Unlock()
		log.Printf("Node %d: Failed to serialize Prepare for signing: %v", n.ID, err)
		return &pb.Ack{Success: true}, nil // Acknowledged PrePrepare, but failed to send Prepare
	}

	signature, err := n.sign(prepareCoreData)
	if err != nil {
		n.mu.Unlock()
		log.Printf("Node %d: Failed to sign Prepare for seq %d: %v", n.ID, req.SequenceNumber, err)
		return &pb.Ack{Success: true}, nil
	}

	prepareMsg := &pb.PrepareRequest{
		View:           req.View,
		SequenceNumber: req.SequenceNumber,
		Digest:         req.Digest,
		ReplicaId:      int32(n.ID),
		Signature:      signature,
	}
	n.mu.Unlock()

	go n.sendToPeer(primaryID, prepareMsg, "Prepare")

	return &pb.Ack{Success: true}, nil
}

// SendPrepare is called by backups, handled by the primary.
// Implements "Crash" attack
func (n *Node) SendPrepare(ctx context.Context, req *pb.PrepareRequest) (*pb.Ack, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// --- Check if we're in a view change ---
	if n.State == StateViewChanging && req.View < n.View {
		log.Printf("Node %d: In ViewChanging state, ignoring old Prepare for view %d", n.ID, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "node in view change"}, nil
	}

	log.Printf("Node %d (Primary) received Prepare from %d for seq=%d view=%d", n.ID, req.ReplicaId, req.SequenceNumber, req.View)

	// --- Validation ---
	if n.getPrimaryID(req.View) != n.ID {
		log.Printf("Node %d: Received Prepare for view %d, but I am not primary.", n.ID, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "not primary for this view"}, nil
	}
	if req.View < n.View {
		log.Printf("Node %d: Received Prepare for old view %d (current %d)", n.ID, req.View, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	entry, ok := n.MessageLog[req.SequenceNumber]
	if !ok || entry.Status == StatusNone || entry.View != req.View || entry.PrePrepareMsg == nil {
		log.Printf("Node %d: Received Prepare for unknown or non-matching PrePrepare (seq=%d, view=%d)", n.ID, req.SequenceNumber, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "no matching PrePrepare"}, nil
	}

	if !bytes.Equal(entry.Digest, req.Digest.Hash) {
		log.Printf("Node %d: Received Prepare with digest mismatch (seq=%d, view=%d)", n.ID, req.SequenceNumber, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "digest mismatch"}, nil
	}

	prepareCoreData, err := prepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash, req.ReplicaId)
	if err != nil {
		log.Printf("Node %d: Failed to serialize Prepare for verification: %v", n.ID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
	}

	if !n.verify(int(req.ReplicaId), prepareCoreData, req.Signature) {
		log.Printf("Node %d: Received Prepare with invalid signature from %d", n.ID, req.ReplicaId)
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}

	// --- Store and Check Quorum ---
	if _, ok := entry.PrepareVotes[int(req.ReplicaId)]; ok {
		log.Printf("Node %d: Received duplicate Prepare from %d for seq %d", n.ID, req.ReplicaId, req.SequenceNumber)
	}
	entry.PrepareVotes[int(req.ReplicaId)] = req

	// Check for quorum (2f + 1 total = 5).
	// Primary's "vote" is implicit (it sent the PrePrepare).
	// So we need 2f = 4 backup votes.
	if len(entry.PrepareVotes) >= (n.QuorumSize-1) && entry.Status == StatusPrePrepared {

		// --- Attack Logic: Crash (as Primary) ---
		// As per PDF: (a) refrains from ... send[ing] prepare messages [FullPrepare]
		if n.AttackModes["crash"] {
			log.Printf("Node %d (Primary) [ATTACK]: Crashing. Reached Prepare quorum for seq %d but will not send FullPrepare.", n.ID, req.SequenceNumber)
			entry.Status = StatusPrepared      // Log it
			return &pb.Ack{Success: true}, nil // Lie and say we're fine
		}
		// --- End Attack Logic ---

		entry.Status = StatusPrepared
		log.Printf("Node %d (Primary) has prepared seq=%d. Broadcasting FullPrepare.", n.ID, req.SequenceNumber)

		// --- Broadcast FullPrepare ---
		proofs := make([]*pb.PrepareRequest, 0, len(entry.PrepareVotes))
		for _, proof := range entry.PrepareVotes {
			proofs = append(proofs, proof)
		}

		fullPrepareMsg := &pb.FullPrepareRequest{
			PrePrepareProof: entry.PrePrepareMsg,
			PrepareProofs:   proofs,
		}

		// Unlock before broadcast
		n.mu.Unlock()
		for peerID := range n.NodeAddrs {
			if peerID == n.ID {
				continue
			} // Don't send to self

			// Use generic helper (checks for in-dark)
			go n.sendToPeer(peerID, fullPrepareMsg, "FullPrepare")
		}
		// Re-lock because defer Unlock will fire
		n.mu.Lock()
	}

	return &pb.Ack{Success: true}, nil
}

// SendFullPrepare is called by the primary, handled by backups.
// Implements "Crash" attack
func (n *Node) SendFullPrepare(ctx context.Context, req *pb.FullPrepareRequest) (*pb.Ack, error) {
	n.mu.Lock()

	// --- Check if we're in a view change ---
	if req.PrePrepareProof != nil && n.State == StateViewChanging && req.PrePrepareProof.View < n.View {
		log.Printf("Node %d: In ViewChanging state, ignoring old FullPrepare for view %d", n.ID, req.PrePrepareProof.View)
		n.mu.Unlock()
		return &pb.Ack{Success: false, ErrorMessage: "node in view change"}, nil
	}

	if req.PrePrepareProof == nil {
		n.mu.Unlock()
		log.Printf("Node %d: Received FullPrepare with missing PrePrepare proof", n.ID)
		return &pb.Ack{Success: false, ErrorMessage: "missing PrePrepare proof"}, nil
	}

	v := req.PrePrepareProof.View
	n_seq := req.PrePrepareProof.SequenceNumber
	d_hash := req.PrePrepareProof.Digest.Hash

	// --- Attack Logic: Crash (as Backup) ---
	// PDF: (a) fails to send any prepare messages [here, Commit]
	if n.AttackModes["crash"] {
		log.Printf("Node %d (Backup) [ATTACK]: Crashing. Received FullPrepare for seq %d but will not send Commit.", n.ID, n_seq)
		n.mu.Unlock()
		// We could validate and log, but for a crash, let's just stop.
		return &pb.Ack{Success: true}, nil // Lie and say we're fine
	}
	// --- End Attack Logic ---

	defer n.mu.Unlock() // Normal logic
	primaryID := n.getPrimaryID(v)
	log.Printf("Node %d (Backup) received FullPrepare: seq=%d view=%d", n.ID, n_seq, v)

	// --- Full Validation ---
	if v < n.View {
		log.Printf("Node %d: Received FullPrepare for old view %d (current %d)", n.ID, v, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}
	// TODO: Handle v > n.View

	prePrepareCoreData, err := prePrepareDataForSig(v, n_seq, d_hash)
	if err != nil {
		log.Printf("Node %d: Failed to serialize PrePrepare for verification: %v", n.ID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
	}
	if !n.verify(primaryID, prePrepareCoreData, req.PrePrepareProof.Signature) {
		log.Printf("Node %d: Invalid signature on PrePrepareProof from primary %d", n.ID, primaryID)
		return &pb.Ack{Success: false, ErrorMessage: "invalid PrePrepare signature"}, nil
	}

	if len(req.PrepareProofs) < (n.QuorumSize - 1) { // Need 2f=4 proofs
		log.Printf("Node %d: Received FullPrepare with insufficient proofs (%d)", n.ID, len(req.PrepareProofs))
		return &pb.Ack{Success: false, ErrorMessage: "insufficient prepare proofs"}, nil
	}

	prepareSigners := make(map[int]bool)
	for _, prep := range req.PrepareProofs {
		if prep.View != v || prep.SequenceNumber != n_seq || !bytes.Equal(prep.Digest.Hash, d_hash) {
			log.Printf("Node %d: Received FullPrepare with inconsistent Prepare proof from %d", n.ID, prep.ReplicaId)
			return &pb.Ack{Success: false, ErrorMessage: "inconsistent prepare proof"}, nil
		}
		prepareCoreData, err := prepareDataForSig(v, n_seq, d_hash, prep.ReplicaId)
		if err != nil {
			log.Printf("Node %d: Failed to serialize Prepare for verification (proof from %d): %v", n.ID, prep.ReplicaId, err)
			return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
		}
		if !n.verify(int(prep.ReplicaId), prepareCoreData, prep.Signature) {
			log.Printf("Node %d: Received FullPrepare with invalid Prepare signature from %d", n.ID, prep.ReplicaId)
			return &pb.Ack{Success: false, ErrorMessage: "invalid prepare signature"}, nil
		}
		prepareSigners[int(prep.ReplicaId)] = true
	}
	if len(prepareSigners) < (n.QuorumSize - 1) {
		log.Printf("Node %d: Received FullPrepare with non-distinct proofs (got %d, need %d)", n.ID, len(prepareSigners), n.QuorumSize-1)
		return &pb.Ack{Success: false, ErrorMessage: "non-distinct prepare proofs"}, nil
	}

	// --- Log and Prepare ---
	entry, ok := n.MessageLog[n_seq]
	if !ok {
		d, err := digest(req.PrePrepareProof.Request)
		if err != nil || !bytes.Equal(d, d_hash) {
			log.Printf("Node %d: Digest mismatch for request in FullPrepare seq %d!", n.ID, n_seq)
			return &pb.Ack{Success: false, ErrorMessage: "digest mismatch on request"}, nil
		}

		n.MessageLog[n_seq] = &InternalLogEntry{
			SequenceNumber: n_seq,
			View:           v,
			Digest:         d,
			Request:        req.PrePrepareProof.Request,
			Status:         StatusPrepared, // We have proof, so mark prepared
			PrePrepareMsg:  req.PrePrepareProof,
			PrepareVotes:   make(map[int]*pb.PrepareRequest),
			CommitVotes:    make(map[int]*pb.CommitRequest),
		}
		entry = n.MessageLog[n_seq]
	} else if entry.Status == StatusPrePrepared {
		entry.Status = StatusPrepared
	}

	entry.FullPrepareRx = true
	for _, p := range req.PrepareProofs {
		entry.PrepareVotes[int(p.ReplicaId)] = p
	}

	log.Printf("Node %d (Backup) has prepared seq=%d.", n.ID, n_seq)

	// --- Send Commit back to Primary (Linear Step) ---
	commitCoreData, err := commitDataForSig(v, n_seq, d_hash, int32(n.ID))
	if err != nil {
		log.Printf("Node %d: Failed to serialize Commit for signing: %v", n.ID, err)
		return &pb.Ack{Success: true}, nil
	}
	signature, err := n.sign(commitCoreData)
	if err != nil {
		log.Printf("Node %d: Failed to sign Commit for seq %d: %v", n.ID, n_seq, err)
		return &pb.Ack{Success: true}, nil
	}

	commitMsg := &pb.CommitRequest{
		View:           v,
		SequenceNumber: n_seq,
		Digest:         req.PrePrepareProof.Digest,
		ReplicaId:      int32(n.ID),
		Signature:      signature,
	}

	n.mu.Unlock() // Unlock before network call

	// Use generic helper (checks for in-dark)
	go n.sendToPeer(primaryID, commitMsg, "Commit")

	// Re-lock
	n.mu.Lock()

	return &pb.Ack{Success: true}, nil
}

// SendCommit is called by backups, handled by the primary.
// Implements "Crash" attack
func (n *Node) SendCommit(ctx context.Context, req *pb.CommitRequest) (*pb.Ack, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// --- Check if we're in a view change ---
	if n.State == StateViewChanging && req.View < n.View {
		log.Printf("Node %d: In ViewChanging state, ignoring old Commit for view %d", n.ID, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "node in view change"}, nil
	}

	log.Printf("Node %d (Primary) received Commit from %d: seq=%d view=%d", n.ID, req.ReplicaId, req.SequenceNumber, req.View)

	// --- Validation ---
	if n.getPrimaryID(req.View) != n.ID {
		return &pb.Ack{Success: false, ErrorMessage: "not primary for this view"}, nil
	}
	if req.View < n.View {
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}
	entry, ok := n.MessageLog[req.SequenceNumber]
	if !ok || entry.View != req.View {
		return &pb.Ack{Success: false, ErrorMessage: "no matching log entry"}, nil
	}
	// Must be at least prepared to accept commits
	if entry.Status == StatusPrePrepared {
		return &pb.Ack{Success: false, ErrorMessage: "entry not prepared"}, nil
	}
	if !bytes.Equal(entry.Digest, req.Digest.Hash) {
		return &pb.Ack{Success: false, ErrorMessage: "digest mismatch"}, nil
	}
	commitCoreData, err := commitDataForSig(req.View, req.SequenceNumber, req.Digest.Hash, req.ReplicaId)
	if err != nil {
		return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
	}
	if !n.verify(int(req.ReplicaId), commitCoreData, req.Signature) {
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}

	// --- Store and Check Quorum ---
	if _, ok := entry.CommitVotes[int(req.ReplicaId)]; ok {
		log.Printf("Node %d: Received duplicate Commit from %d for seq %d", n.ID, req.ReplicaId, req.SequenceNumber)
	}
	entry.CommitVotes[int(req.ReplicaId)] = req

	// We need 2f = 4 backup votes.
	if len(entry.CommitVotes) >= (n.QuorumSize-1) && entry.Status == StatusPrepared {

		// --- Attack Logic: Crash (as Primary) ---
		// PDF: (a) refrains from ... send[ing] prepare messages [FullCommit]
		if n.AttackModes["crash"] {
			log.Printf("Node %d (Primary) [ATTACK]: Crashing. Reached Commit quorum for seq %d but will not send FullCommit or Execute.", n.ID, req.SequenceNumber)
			entry.Status = StatusCommitted     // Log it
			return &pb.Ack{Success: true}, nil // Lie and say we're fine
		}
		// --- End Attack Logic ---

		entry.Status = StatusCommitted
		log.Printf("Node %d (Primary) has committed seq=%d.", n.ID, req.SequenceNumber)

		// --- Execute and Reply (as Primary) ---
		n.attemptExecution() // This function handles ordered execution and replying

		// --- Broadcast FullCommit ---
		proofs := make([]*pb.CommitRequest, 0, len(entry.CommitVotes))
		for _, proof := range entry.CommitVotes {
			proofs = append(proofs, proof)
		}
		fullCommitMsg := &pb.FullCommitRequest{
			View:           req.View,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			CommitProofs:   proofs,
		}

		// Unlock before broadcast
		n.mu.Unlock()
		for peerID := range n.NodeAddrs {
			if peerID == n.ID {
				continue
			}
			// Use generic helper (checks for in-dark)
			go n.sendToPeer(peerID, fullCommitMsg, "FullCommit")
		}
		// Re-lock
		n.mu.Lock()
	}

	return &pb.Ack{Success: true}, nil
}

// SendFullCommit is called by the primary, handled by backups.
func (n *Node) SendFullCommit(ctx context.Context, req *pb.FullCommitRequest) (*pb.Ack, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// --- Check if we're in a view change ---
	if n.State == StateViewChanging && req.View < n.View {
		log.Printf("Node %d: In ViewChanging state, ignoring old FullCommit for view %d", n.ID, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "node in view change"}, nil
	}

	log.Printf("Node %d (Backup) received FullCommit: seq=%d view=%d", n.ID, req.SequenceNumber, req.View)

	v := req.View
	n_seq := req.SequenceNumber
	d_hash := req.Digest.Hash

	// --- Full Validation ---
	if v < n.View {
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	if len(req.CommitProofs) < (n.QuorumSize - 1) { // Need 2f=4 proofs
		return &pb.Ack{Success: false, ErrorMessage: "insufficient commit proofs"}, nil
	}

	commitSigners := make(map[int]bool)
	for _, com := range req.CommitProofs {
		if com.View != v || com.SequenceNumber != n_seq || !bytes.Equal(com.Digest.Hash, d_hash) {
			return &pb.Ack{Success: false, ErrorMessage: "inconsistent commit proof"}, nil
		}
		commitCoreData, err := commitDataForSig(v, n_seq, d_hash, com.ReplicaId)
		if err != nil {
			return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
		}
		if !n.verify(int(com.ReplicaId), commitCoreData, com.Signature) {
			return &pb.Ack{Success: false, ErrorMessage: "invalid commit signature"}, nil
		}
		commitSigners[int(com.ReplicaId)] = true
	}
	if len(commitSigners) < (n.QuorumSize - 1) {
		return &pb.Ack{Success: false, ErrorMessage: "non-distinct commit proofs"}, nil
	}

	// --- Log and Execute ---
	entry, ok := n.MessageLog[n_seq]
	if !ok {
		log.Printf("Node %d: Received FullCommit for unknown seq %d", n.ID, n_seq)
		return &pb.Ack{Success: false, ErrorMessage: "entry not known"}, nil
	}

	// Only move to committed if it was prepared
	if entry.Status == StatusPrepared {
		entry.Status = StatusCommitted
	}
	entry.FullCommitRx = true

	log.Printf("Node %d (Backup) has committed seq=%d.", n.ID, n_seq)

	// Execute request (must be in order)
	n.attemptExecution()

	return &pb.Ack{Success: true}, nil
}

// attemptExecution is a helper function to execute all possible
// requests in strict sequence order.
// Stops timers and implements "Crash" attack for replies.
// MUST be called with the lock held.
func (n *Node) attemptExecution() {
	for {
		seqToExec := n.LastExecuted + 1
		entry, ok := n.MessageLog[seqToExec]
		if !ok {
			// We haven't even heard of the next request, so we must stop.
			break
		}

		if entry.Status != StatusCommitted {
			// The next required request is not committed yet, so we stop.
			break
		}

		// --- STOP THE TIMER ---
		// We have committed and are about to execute. Stop the timer for this seq num.
		if timer, ok := n.requestTimers[seqToExec]; ok {
			timer.Stop()
			delete(n.requestTimers, seqToExec)
			log.Printf("Node %d stopped timer for executed seq %d", n.ID, seqToExec)
		}
		// --- END TIMER LOGIC ---

		// --- Execute the request ---
		result := "success" // Default to success for no-ops
		if entry.Request != nil {
			tx := entry.Request.Transaction

			// --- Handle Read-Only Request ---
			// A read-only request has a sender but no receiver/amount
			if tx.Receiver == "" && tx.Amount == 0 && entry.Request.ClientId != "no-op" {
				if val, ok := n.DB[tx.Sender]; ok {
					result = fmt.Sprintf("Balance: %d", val)
				} else {
					n.DB[tx.Sender] = 10 // Initialize if not present
					result = "Balance: 10"
				}
			} else if entry.Request.ClientId != "no-op" {
				// --- Handle Read-Write Request ---
				if _, ok := n.DB[tx.Sender]; !ok {
					n.DB[tx.Sender] = 10
				}
				if _, ok := n.DB[tx.Receiver]; !ok {
					n.DB[tx.Receiver] = 10
				}

				if n.DB[tx.Sender] >= tx.Amount {
					n.DB[tx.Sender] -= tx.Amount
					n.DB[tx.Receiver] += tx.Amount
				} else {
					result = "failed: insufficient funds"
				}
			}
			// If it's a "no-op", result just stays "success"
		}

		entry.Status = StatusExecuted
		n.LastExecuted = seqToExec
		log.Printf("Node %d EXECUTED seq=%d with result: %s", n.ID, seqToExec, result)

		// TODO: Trigger checkpointing if n.LastExecuted % CheckpointPeriod == 0

		// --- Reply to Client (if this node has a pending handler) ---
		if entry.Request != nil && entry.Request.ClientId != "no-op" {
			reqKey := fmt.Sprintf("%s-%d", entry.Request.ClientId, entry.Request.Timestamp)

			// Check if we have a pending client reply channel for this request
			if replyChan, ok := n.pendingClientReplies[reqKey]; ok {

				replyCoreData, err := clientReplyDataForSig(entry.View, entry.Request.Timestamp, entry.Request.ClientId, int32(n.ID), result)
				if err != nil {
					log.Printf("Node %d: Failed to serialize reply for signing: %v", n.ID, err)
					continue
				}

				signature, err := n.sign(replyCoreData)
				if err != nil {
					log.Printf("Node %d: Failed to sign reply for seq %d: %v", n.ID, seqToExec, err)
					continue
				}

				clientReply := &pb.ClientReply{
					View:      entry.View,
					Timestamp: entry.Request.Timestamp,
					ClientId:  entry.Request.ClientId,
					ReplicaId: int32(n.ID),
					Result:    result,
					Signature: signature,
				}

				// --- Attack Logic: Crash (Reply) ---
				// PDF: "does not send reply messages back to clients"
				if n.AttackModes["crash"] {
					log.Printf("Node %d [ATTACK]: Crashing. *NOT* sending reply for seq %d to client.", n.ID, seqToExec)
					// We just don't send on the channel. The client will time out.
				} else {
					// --- Normal Reply ---
					// Send the reply back to the original SubmitRequest goroutine
					select {
					case replyChan <- clientReply:
						log.Printf("Node %d sent reply for seq=%d (key=%s) to client handler", n.ID, seqToExec, reqKey)
					default:
						log.Printf("Node %d reply channel for seq=%d (key=%s) was full/closed.", n.ID, seqToExec, reqKey)
					}
				}
			}
		}
		// Loop again to try executing the *next* sequence number
	}
}

// handleRequestTimeout is called when a backup's timer fires
func (n *Node) handleRequestTimeout(seqNum int64, view int32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// 1. Check if the request was already executed or the view has changed
	if entry, ok := n.MessageLog[seqNum]; ok && entry.Status == StatusExecuted {
		log.Printf("Node %d: Timer fired for seq %d, but it was already executed. Ignoring.", n.ID, seqNum)
		delete(n.requestTimers, seqNum)
		return
	}

	if n.View != view {
		log.Printf("Node %d: Timer fired for seq %d (view %d), but we are in view %d. Ignoring.", n.ID, seqNum, view, n.View)
		delete(n.requestTimers, seqNum)
		return
	}

	// 2. If we are already view-changing for this *next* view, ignore
	if n.State == StateViewChanging && n.viewChangeVotes[n.View+1] != nil {
		log.Printf("Node %d: Timer fired for seq %d, but already changing to view %d.", n.ID, seqNum, n.View+1)
		return
	}

	// 3. Trigger a View Change
	log.Printf("Node %d: TIMER EXPIRED for seq %d (view %d). Leader is faulty! TRIGGERING VIEW CHANGE.", n.ID, seqNum, view)
	delete(n.requestTimers, seqNum)

	n.startViewChange()
}

// startViewChange begins the view change protocol
func (n *Node) startViewChange() {
	// This function must be called with the lock HELD

	newView := n.View + 1
	n.State = StateViewChanging
	n.View = newView // Tentatively update view to stop processing old messages
	log.Printf("Node %d: Entering state %s for view %d", n.ID, n.State, newView)

	// Clear out any old request timers
	for seq, timer := range n.requestTimers {
		timer.Stop()
		delete(n.requestTimers, seq)
	}

	// --- 1. Build the P-set (Prepared Proofs) ---
	// Per PDF, this includes requests that the replica has prepared.
	// Since checkpointing is a bonus, min-s (last checkpoint) is 0.
	// So we look for *all* prepared messages in our log.

	preparedProofs := make([]*pb.PProof, 0)
	for _, entry := range n.MessageLog {
		// We only need to send proof for requests that are *at least* prepared
		// but *not* yet executed (or committed, as execution is the final state)
		if entry.Status == StatusPrepared && entry.PrePrepareMsg != nil {

			// We need 2f matching Prepare messages. In our Linear model,
			// the backup only gets these in a FullPrepareRequest.
			if entry.FullPrepareRx {
				log.Printf("Node %d: Adding seq %d to P-set for view change", n.ID, entry.SequenceNumber)

				// Collect the 2f votes
				votes := make([]*pb.PrepareRequest, 0, len(entry.PrepareVotes))
				for _, vote := range entry.PrepareVotes {
					votes = append(votes, vote)
				}

				proof := &pb.PProof{
					PrePrepareReq: entry.PrePrepareMsg,
					PrepareReqs:   votes,
				}
				preparedProofs = append(preparedProofs, proof)
			}
		}
	}

	// --- 2. Create and Sign the ViewChangeRequest ---
	// As per PDF, checkpoint cert is not needed and min-s=0.
	vcRequest := &pb.ViewChangeRequest{
		NewView:          newView,
		CheckpointSeqNum: 0,   // No checkpoints
		CheckpointProof:  nil, // No checkpoints
		PreparedProof:    preparedProofs,
		ReplicaId:        int32(n.ID),
	}

	// We need to sign this. The signature is over <VIEW-CHANGE, v+1, n, C, P, i>
	// We'll create a simple helper to serialize this.
	vcData, err := viewChangeDataForSig(vcRequest)
	if err != nil {
		log.Printf("Node %d: Failed to serialize ViewChangeRequest for signing: %v", n.ID, err)
		return // Can't proceed
	}
	signature, err := n.sign(vcData)
	if err != nil {
		log.Printf("Node %d: Failed to sign ViewChangeRequest: %v", n.ID, err)
		return // Can't proceed
	}
	vcRequest.Signature = signature

	// --- 3. Store our own vote and broadcast ---
	if _, ok := n.viewChangeVotes[newView]; !ok {
		n.viewChangeVotes[newView] = make(map[int]*pb.ViewChangeRequest)
	}
	n.viewChangeVotes[newView][n.ID] = vcRequest

	n.mu.Unlock() // Unlock before broadcasting
	log.Printf("Node %d: Broadcasting ViewChangeRequest for view %d...", n.ID, newView)
	for peerID := range n.NodeAddrs {
		//if peerID == n.ID { continue } // We should send to ourselves too
		go n.sendToPeer(peerID, vcRequest, "ViewChange")
	}
	n.mu.Lock() // Re-lock
}

// viewChangeDataForSig serializes the core ViewChange fields for signing/verification
func viewChangeDataForSig(req *pb.ViewChangeRequest) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(req.NewView); err != nil {
		return nil, err
	}
	if err := enc.Encode(req.CheckpointSeqNum); err != nil {
		return nil, err
	}

	// We need a deterministic hash of the P-set
	// For simplicity, we'll just encode the number of proofs
	// A real implementation would hash the digests of all P-set entries
	if err := enc.Encode(len(req.PreparedProof)); err != nil {
		return nil, err
	}

	if err := enc.Encode(req.ReplicaId); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- View Change and Other Placeholders ---

// SendViewChange is called by other nodes
func (n *Node) SendViewChange(ctx context.Context, req *pb.ViewChangeRequest) (*pb.Ack, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	senderID := int(req.ReplicaId)
	newView := req.NewView
	log.Printf("Node %d: Received ViewChange from %d for view %d", n.ID, senderID, newView)

	// --- 1. Validation ---
	if newView < n.View {
		log.Printf("Node %d: Received old ViewChange for view %d (current: %d). Ignoring.", n.ID, newView, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	// Verify signature
	vcData, err := viewChangeDataForSig(req)
	if err != nil {
		log.Printf("Node %d: Failed to serialize ViewChange from %d for verification: %v", n.ID, senderID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
	}
	if !n.verify(senderID, vcData, req.Signature) {
		log.Printf("Node %d: Received ViewChange from %d with INVALID signature. Ignoring.", n.ID, senderID)
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}

	// TODO: Validate the P-set in the request

	// --- 2. Store the Vote ---
	if _, ok := n.viewChangeVotes[newView]; !ok {
		n.viewChangeVotes[newView] = make(map[int]*pb.ViewChangeRequest)
	}
	// Prevent duplicate votes
	if _, ok := n.viewChangeVotes[newView][senderID]; ok {
		log.Printf("Node %d: Received duplicate ViewChange from %d for view %d. Ignoring.", n.ID, senderID, newView)
		return &pb.Ack{Success: false, ErrorMessage: "duplicate view change message"}, nil
	}
	n.viewChangeVotes[newView][senderID] = req
	log.Printf("Node %d: Stored ViewChange vote from %d for view %d. Total votes: %d/%d", n.ID, senderID, newView, len(n.viewChangeVotes[newView]), n.QuorumSize)

	// --- 3. Check for Quorum (2f+1) ---
	if len(n.viewChangeVotes[newView]) >= n.QuorumSize {
		log.Printf("Node %d: Achieved ViewChange quorum for view %d.", n.ID, newView)

		// If we haven't already, transition our own state
		if n.State != StateViewChanging || n.View < newView {
			// This node was loyal and didn't start its own view change.
			// It needs to trigger it now to catch up.
			log.Printf("Node %d: Quorum received, triggering catch-up view change.", n.ID)
			n.startViewChange()
		}

		// --- 4. If WE are the new Primary, send NewView ---
		newPrimaryID := n.getPrimaryID(newView)
		if n.ID == newPrimaryID {

			if n.AttackModes["crash"] {
				log.Printf("Node %d (Primary) [ATTACK]: Crashing. Received ViewChange quorum but will not send NewView.", n.ID)
				return &pb.Ack{Success: true}, nil // Lie and say we're fine
			}

			log.Printf("Node %d: I AM THE NEW PRIMARY for view %d. Preparing NewView message.", n.ID, newView)
			n.sendNewView(newView) // This is a new helper function
		}
	}

	return &pb.Ack{Success: true}, nil
}

// sendNewView is called by the new primary after a ViewChange quorum
func (n *Node) sendNewView(newView int32) {
	// This function must be called with the lock HELD
	log.Printf("Node %d (Primary): Constructing NewView for view %d", n.ID, newView)

	// --- 1. Get the 2f+1 ViewChange messages (the V-set) ---
	vSet := n.viewChangeVotes[newView]
	vSetProofs := make([]*pb.ViewChangeRequest, 0, len(vSet))
	for _, vote := range vSet {
		vSetProofs = append(vSetProofs, vote)
	}

	// --- 2. Determine min-s and max-s ---
	// min-s is 0 (no checkpoints)
	// max-s is the highest sequence number in any P-set
	minS := int64(0)
	maxS := int64(0)
	// We also need to find the "best" request for each sequence number
	// Key: seqNum, Value: the request with the highest view
	bestPSet := make(map[int64]*pb.PrePrepareRequest)

	for _, vcMsg := range vSet {
		for _, pProof := range vcMsg.PreparedProof {
			seq := pProof.PrePrepareReq.SequenceNumber
			view := pProof.PrePrepareReq.View

			if seq > maxS {
				maxS = seq
			}

			// Check if we have a proof for this seq num already
			if existing, ok := bestPSet[seq]; ok {
				// If this proof is from a higher view, it's better
				if view > existing.View {
					bestPSet[seq] = pProof.PrePrepareReq
				}
			} else {
				// No proof yet, this is the best one so far
				bestPSet[seq] = pProof.PrePrepareReq
			}
		}
	}

	log.Printf("Node %d (Primary): Calculated minS=%d, maxS=%d for new view", n.ID, minS, maxS)

	// --- 3. Determine the O-set (new PrePrepares) ---
	oSet := make([]*pb.PrePrepareRequest, 0)

	for n_seq := minS + 1; n_seq <= maxS; n_seq++ {
		var newPrePrepare *pb.PrePrepareRequest

		if bestReq, ok := bestPSet[n_seq]; ok {
			// --- Case 1: A request was prepared. Re-propose it. ---
			log.Printf("Node %d (Primary): Re-proposing seq %d for new view", n.ID, n_seq)
			// We must sign this new PrePrepare with the *new view*
			d, _ := digest(bestReq.Request)
			newPrePrepare, _ = n.createSignedPrePrepare(newView, n_seq, d, bestReq.Request)

		} else {
			// --- Case 2: No request was prepared. Propose a "no-op". ---
			log.Printf("Node %d (Primary): Proposing NO-OP for seq %d for new view", n.ID, n_seq)
			// A no-op is just a nil request. The digest is of an empty request.
			noOpReq := &pb.ClientRequest{ClientId: "no-op"}
			d, _ := digest(noOpReq)
			newPrePrepare, _ = n.createSignedPrePrepare(newView, n_seq, d, noOpReq)
		}

		oSet = append(oSet, newPrePrepare)
		// We also need to log these new PrePrepares ourselves
		n.logPrePrepare(newPrePrepare)
	}

	// Update our own SeqNum to be the new max
	n.SeqNum = maxS

	// --- 4. Create, sign, and broadcast the NewView message ---
	newViewRequest := &pb.NewViewRequest{
		NewView:            newView,
		ViewChangeProof:    vSetProofs,
		ReproposedRequests: oSet,
	}

	// We need a deterministic way to sign this
	// For now, let's just sign the view number and number of proofs
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(struct {
		V int32
		O int
	}{newView, len(oSet)}); err != nil {
		// Handle the error, e.g., log it and return
		log.Printf("Node %d (Primary): Failed to encode NewView for signing: %v", n.ID, err)
		return
	}
	nvData := buf.Bytes()
	signature, err := n.sign(nvData)
	if err != nil {
		log.Printf("Node %d (Primary): Failed to sign NewView: %v", n.ID, err)
		return
	}
	newViewRequest.Signature = signature

	// We are now in the new view
	n.State = StateNormal
	n.View = newView

	n.mu.Unlock() // Unlock before broadcasting
	log.Printf("Node %d (Primary): Broadcasting NewView for view %d", n.ID, newView)
	for peerID := range n.NodeAddrs {
		go n.sendToPeer(peerID, newViewRequest, "NewView")
	}
	n.mu.Lock() // Re-lock
}

// SendNewView is called by the new primary, handled by backups
func (n *Node) SendNewView(ctx context.Context, req *pb.NewViewRequest) (*pb.Ack, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	newView := req.NewView
	senderID := n.getPrimaryID(newView)
	log.Printf("Node %d: Received NewView from primary %d for view %d", n.ID, senderID, newView)

	// --- 1. Validation ---
	if newView < n.View {
		log.Printf("Node %d: Received old NewView for view %d (current: %d). Ignoring.", n.ID, newView, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	// Validate signature
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(struct {
		V int32
		O int
	}{newView, len(req.ReproposedRequests)}); err != nil {
		log.Printf("Node %d: Failed to encode NewView for signature verification: %v", n.ID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
	}
	nvData := buf.Bytes()
	if !n.verify(senderID, nvData, req.Signature) {
		log.Printf("Node %d: Received NewView from %d with INVALID signature. Ignoring.", n.ID, senderID)
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}

	// Validate V-set (the ViewChange proofs)
	if len(req.ViewChangeProof) < n.QuorumSize {
		log.Printf("Node %d: Received NewView with insufficient V-set proofs (%d/%d). Ignoring.", n.ID, len(req.ViewChangeProof), n.QuorumSize)
		return &pb.Ack{Success: false, ErrorMessage: "insufficient view change proofs"}, nil
	}

	// TODO: Full validation would re-verify every signature in the V-set
	// For now, we trust the primary did this.
	// TODO: Validate O-set against V-set

	// --- 2. State Transition ---
	n.State = StateNormal
	n.View = newView
	n.SeqNum = n.LastExecuted // Reset SeqNum, will be updated by O-set

	// Clear old timers
	for seq, timer := range n.requestTimers {
		timer.Stop()
		delete(n.requestTimers, seq)
	}
	// Clear old view change votes
	n.viewChangeVotes = make(map[int32]map[int]*pb.ViewChangeRequest)

	log.Printf("Node %d (Backup): ACCEPTED NewView. Transitioned to view %d.", n.ID, newView)

	// --- 3. Process the O-set (new PrePrepares) ---
	n.mu.Unlock() // Unlock to call logPrePrepare (which locks)
	var maxSeq int64 = 0
	for _, prePrepare := range req.ReproposedRequests {
		n.logAndProcessPrePrepare(prePrepare)
		if prePrepare.SequenceNumber > maxSeq {
			maxSeq = prePrepare.SequenceNumber // Update our sequence number
		}
	}
	n.mu.Lock() // Re-lock
	n.SeqNum = maxSeq

	return &pb.Ack{Success: true}, nil
}

// logAndProcessPrePrepare is a helper for backups to handle re-proposed requests
func (n *Node) logAndProcessPrePrepare(req *pb.PrePrepareRequest) {
	n.mu.Lock()

	// 1. Log the new PrePrepare
	if !n.logPrePrepare(req) {
		log.Printf("Node %d (Backup): Failed to log re-proposed PrePrepare for seq %d", n.ID, req.SequenceNumber)
		n.mu.Unlock()
		return
	}

	// 2. Start the request timer
	if timer, ok := n.requestTimers[req.SequenceNumber]; ok {
		timer.Stop()
	}
	n.requestTimers[req.SequenceNumber] = time.AfterFunc(RequestTimeout, func() {
		n.handleRequestTimeout(req.SequenceNumber, req.View)
	})

	// 3. Send Prepare to the new primary
	prepareCoreData, err := prepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash, int32(n.ID))
	if err != nil {
		log.Printf("Node %d: Failed to serialize Prepare for signing: %v", n.ID, err)
		n.mu.Unlock()
		return
	}
	signature, err := n.sign(prepareCoreData)
	if err != nil {
		log.Printf("Node %d: Failed to sign Prepare for seq %d: %v", n.ID, req.SequenceNumber, err)
		n.mu.Unlock()
		return
	}

	prepareMsg := &pb.PrepareRequest{
		View:           req.View,
		SequenceNumber: req.SequenceNumber,
		Digest:         req.Digest,
		ReplicaId:      int32(n.ID),
		Signature:      signature,
	}

	n.mu.Unlock() // Unlock before sending
	go n.sendToPeer(n.getPrimaryID(req.View), prepareMsg, "Prepare")
}

// logPrePrepare is a helper to log a PrePrepare (used by primary and backups)
func (n *Node) logPrePrepare(req *pb.PrePrepareRequest) bool {
	// Assumes lock is HELD

	d, err := digest(req.Request)
	if err != nil || !bytes.Equal(d, req.Digest.Hash) {
		log.Printf("Node %d: Digest mismatch for logging PrePrepare seq %d!", n.ID, req.SequenceNumber)
		return false
	}

	if _, ok := n.MessageLog[req.SequenceNumber]; !ok {
		n.MessageLog[req.SequenceNumber] = &InternalLogEntry{
			SequenceNumber: req.SequenceNumber,
			View:           req.View,
			Digest:         req.Digest.Hash,
			Request:        req.Request,
			Status:         StatusPrePrepared,
			PrePrepareMsg:  req,
			PrepareVotes:   make(map[int]*pb.PrepareRequest),
			CommitVotes:    make(map[int]*pb.CommitRequest),
		}
	} else {
		// Entry exists, just update it
		n.MessageLog[req.SequenceNumber].View = req.View
		n.MessageLog[req.SequenceNumber].Status = StatusPrePrepared
		n.MessageLog[req.SequenceNumber].PrePrepareMsg = req
		n.MessageLog[req.SequenceNumber].FullPrepareRx = false // Reset proofs
		n.MessageLog[req.SequenceNumber].FullCommitRx = false
		n.MessageLog[req.SequenceNumber].PrepareVotes = make(map[int]*pb.PrepareRequest)
		n.MessageLog[req.SequenceNumber].CommitVotes = make(map[int]*pb.CommitRequest)
	}
	return true
}

// SendCheckpoint is a placeholder
func (n *Node) SendCheckpoint(ctx context.Context, req *pb.Checkpoint) (*pb.Ack, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	log.Printf("Node %d received Checkpoint from %d for seq %d", n.ID, req.ReplicaId, req.SequenceNumber)
	// TODO: Implement Checkpoint collection and state
	return &pb.Ack{Success: true, ErrorMessage: "unimplemented"}, nil
}

// GetNodeState is called by the test harness
func (n *Node) GetNodeState(ctx context.Context, req *pb.StateRequest) (*pb.StateReply, error) {
	log.Printf("Node %d received GetNodeState request", n.ID)
	n.mu.Lock()
	defer n.mu.Unlock()

	// Build simplified log for printing
	simpleLog := make([]*pb.LogEntry, 0, len(n.MessageLog))

	// Sort keys to print log in order
	keys := make([]int64, 0, len(n.MessageLog))
	for k := range n.MessageLog {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, seq := range keys {
		entry := n.MessageLog[seq]
		content := "NO-OP"
		if entry.Request != nil {
			if entry.Request.ClientId == "no-op" {
				content = "NO-OP"
			} else if entry.Request.Transaction != nil {
				tx := entry.Request.Transaction
				// Differentiate between read-write and read-only
				if tx.Receiver == "" && tx.Amount == 0 {
					content = fmt.Sprintf("(%s)", tx.Sender) // Read-Only
				} else {
					content = fmt.Sprintf("(%s, %s, %d)", tx.Sender, tx.Receiver, tx.Amount)
				}
			}
		}

		simpleLog = append(simpleLog, &pb.LogEntry{
			SequenceNumber: seq,
			Status:         entry.Status,
			Content:        content,
			View:           entry.View,
		})
	}

	// Build simple DB
	dbCopy := make(map[string]int32)
	for k, v := range n.DB {
		dbCopy[k] = v
	}

	status := "X" // Not Found
	if req.SequenceNumber > 0 {
		if entry, ok := n.MessageLog[req.SequenceNumber]; ok {
			status = entry.Status
			if status == "" {
				status = "X"
			}
		}
	}

	// --- Build ViewChange history for PrintView ---
	viewChanges := make([]*pb.ViewChangeRequest, 0)
	// Just grab all the votes we have for all views
	for _, viewMap := range n.viewChangeVotes {
		for _, vcMsg := range viewMap {
			viewChanges = append(viewChanges, vcMsg)
		}
	}

	return &pb.StateReply{
		NodeId:               int32(n.ID),
		CurrentView:          n.View,
		LastSequenceNumber:   n.SeqNum, // This is the primary's next seq num
		LastExecutedSequence: n.LastExecuted,
		Db:                   dbCopy,
		Log:                  simpleLog,
		StatusForSeq:         status,
		ViewChangeHistory:    viewChanges, // Pass the collected VC messages
	}, nil
}
