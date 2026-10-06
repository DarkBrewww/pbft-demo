package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"

	"encoding/gob"
	"fmt"
	"log"

	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	pb "bft-DarkBrewww/proto"
)

type NodeState string

const (
	StateNormal       NodeState = "Normal"
	StateViewChanging NodeState = "ViewChanging"

	RequestTimeout    = 5 * time.Second
	ViewChangeTimeout = 10 * time.Second

	CheckpointInterval = int64(10)

	WatermarkRange = int64(20)

	// MaxInFlight caps how far past its own last executed sequence number the
	// primary may assign sequence numbers. It is half the watermark window so a
	// backup that lags a little behind the primary still accepts the PrePrepare.
	MaxInFlight = WatermarkRange / 2

	// TimingAttackDelay is how long a primary running the "time" attack holds each request.
	TimingAttackDelay = 500 * time.Millisecond

	// MaxClientWait bounds how long a SubmitRequest handler waits for execution
	// if the client did not set a deadline.
	MaxClientWait = 60 * time.Second

	// NoOpClientID marks the no-op requests a new primary proposes for gaps.
	NoOpClientID = "no-op"
)

const (
	StatusNone        = ""
	StatusPrePrepared = "pre-prepared"
	StatusPrepared    = "prepared"
	StatusCommitted   = "committed-local"
	StatusExecuted    = "executed"
)

type InternalLogEntry struct {
	SequenceNumber int64
	View           int32
	Digest         []byte
	Request        *pb.ClientRequest
	Status         string

	PrePrepareMsg *pb.PrePrepareRequest
	PrepareVotes  map[int]*pb.PrepareRequest
	CommitVotes   map[int]*pb.CommitRequest
	FullPrepareRx bool
	FullCommitRx  bool

	// PreparedCert is the prepare certificate (PrePrepare + 2f Prepares) from the
	// highest view in which this entry prepared at this replica. It survives
	// re-proposals in later views so a view change always reports it (PBFT P-set).
	PreparedCert *pb.PProof
}

// pendingRequest is a client request this replica received but has not executed yet.
type pendingRequest struct {
	req     *pb.ClientRequest
	arrival int64
}

// execRecord remembers how a client request was executed, so retransmissions and
// late-arriving copies get the same reply and are never applied twice.
type execRecord struct {
	result string
	view   int32
}

type Node struct {
	pb.UnimplementedPbftNodeServer

	ID           int
	NodeAddrs    map[int]string
	F            int
	N            int
	QuorumSize   int
	ClientQuorum int

	AttackModes         map[string]bool
	darkTargets         map[int]bool
	equivocationTargets map[int]bool
	State               NodeState
	View                int32
	SeqNum              int64
	LastExecuted        int64
	Watermarks          struct{ Low, High int64 }

	MessageLog map[int64]*InternalLogEntry

	DB map[string]int32

	PrivateKey *ecdsa.PrivateKey
	PublicKeys map[int]*ecdsa.PublicKey

	mu          sync.Mutex
	grpcClients map[int]pb.PbftNodeClient
	clientConn  map[int]*grpc.ClientConn

	// Client request bookkeeping (keyed by "<clientId>-<timestamp>")
	pendingRequests map[string]*pendingRequest
	arrivals        int64
	proposedInView  map[string]int32         // requests this node proposed as primary, and in which view
	executedReqs    map[string]execRecord    // executed requests and their results
	execWaiters     map[string]chan struct{} // closed when the request executes

	viewChangeVotes   map[int32]map[int]*pb.ViewChangeRequest
	viewChangeHistory []*pb.ViewChangeRequest // every valid VIEW-CHANGE seen, for printview
	newViewSent       map[int32]bool
	vcAttempts        int // consecutive view changes that timed out (timeout doubles)

	requestTimers map[int64]*time.Timer
	viewTimer     *time.Timer

	//stableCheckpoints    map[int64]*pb.CheckpointProof
	//checkpointVotes      map[int64]map[int]*pb.Checkpoint
	//lastStableCheckpoint int64
}

func NewNode(id int, addrs map[int]string, f int, privKey *ecdsa.PrivateKey, pubKeys map[int]*ecdsa.PublicKey, attackString string) (*Node, error) {
	n := len(addrs)
	if n < (3*f + 1) {
		return nil, fmt.Errorf("insufficient nodes (%d) for f=%d", n, f)
	}
	if id < 0 || id >= n {
		return nil, fmt.Errorf("node ID %d out of range (0-%d)", id, n-1)
	}

	attackModes := make(map[string]bool)
	darkTargets := make(map[int]bool)
	equivocationTargets := make(map[int]bool)
	re := regexp.MustCompile(`n(\d+)`)

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
						darkTargets[targetID-1] = true
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
						equivocationTargets[targetID-1] = true
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

	node := &Node{
		ID:                  id,
		NodeAddrs:           addrs,
		F:                   f,
		N:                   n,
		QuorumSize:          2*f + 1,
		ClientQuorum:        f + 1,
		AttackModes:         attackModes,
		darkTargets:         darkTargets,
		equivocationTargets: equivocationTargets,
		State:               StateNormal,
		View:                0,
		SeqNum:              0,
		LastExecuted:        0,
		Watermarks:          struct{ Low, High int64 }{0, WatermarkRange},
		MessageLog:          make(map[int64]*InternalLogEntry),
		DB:                  make(map[string]int32),
		PrivateKey:          privKey,
		PublicKeys:          pubKeys,
		grpcClients:         make(map[int]pb.PbftNodeClient),
		clientConn:          make(map[int]*grpc.ClientConn),
		pendingRequests:     make(map[string]*pendingRequest),
		proposedInView:      make(map[string]int32),
		executedReqs:        make(map[string]execRecord),
		execWaiters:         make(map[string]chan struct{}),
		requestTimers:       make(map[int64]*time.Timer),
		viewChangeVotes:     make(map[int32]map[int]*pb.ViewChangeRequest),
		newViewSent:         make(map[int32]bool),
		//stableCheckpoints:    make(map[int64]*pb.CheckpointProof),
		//checkpointVotes:      make(map[int64]map[int]*pb.Checkpoint),
		//lastStableCheckpoint: 0,
	}

	for _, client := range []string{"A", "B", "C", "D", "E", "F", "G", "H", "I", "J"} {
		node.DB[client] = 10
	}

	log.Printf("Node %d initialized. N=%d, f=%d, Quorum=%d, ATTACK_MODES: %v, DARK_TARGETS: %v, EQUIV_TARGETS: %v", id, n, f, node.QuorumSize, node.AttackModes, node.darkTargets, node.equivocationTargets)
	return node, nil
}

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

func (n *Node) CloseConnections() {
	n.mu.Lock()
	defer n.mu.Unlock()
	for id, conn := range n.clientConn {
		log.Printf("Node %d closing connection to Node %d", n.ID, id)
		conn.Close()
	}
}

func (n *Node) sign(data []byte) (*pb.Signature, error) {
	if n.PrivateKey == nil {
		return nil, fmt.Errorf("private key not initialized for node %d", n.ID)
	}

	if n.AttackModes["sign"] {
		log.Printf("Node %d [ATTACK]: Generating INVALID signature", n.ID)

		hash := sha256.Sum256(data)
		sigBytes, err := ecdsa.SignASN1(rand.Reader, n.PrivateKey, hash[:])
		if err != nil {
			return nil, fmt.Errorf("failed to sign data: %w", err)
		}

		if len(sigBytes) > 0 {
			sigBytes[len(sigBytes)-1] = ^sigBytes[len(sigBytes)-1]
		}

		return &pb.Signature{
			SignerIdBytes: []byte(fmt.Sprintf("%d", n.ID)),
			Value:         sigBytes,
		}, nil
	}

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

func digest(m *pb.ClientRequest) ([]byte, error) {
	reqBytes, err := proto.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request for digest: %w", err)
	}
	hash := sha256.Sum256(reqBytes)
	return hash[:], nil
}

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

func (n *Node) getPrimaryID(view int32) int {
	return int(view) % n.N
}

func requestKey(req *pb.ClientRequest) string {
	return fmt.Sprintf("%s-%d", req.ClientId, req.Timestamp)
}

// isReadOnly reports a balance query that each replica answers directly (no consensus).
func isReadOnly(tx *pb.Transaction) bool {
	return tx != nil && tx.Receiver == "" && tx.Amount == 0
}

// isConsensusRead reports a balance query the client re-sent through consensus
// after the read-only fast path failed. It is encoded as a zero-amount self-transfer.
func isConsensusRead(tx *pb.Transaction) bool {
	return tx != nil && tx.Sender != "" && tx.Receiver == tx.Sender && tx.Amount == 0
}

func newLogEntry(pp *pb.PrePrepareRequest) *InternalLogEntry {
	return &InternalLogEntry{
		SequenceNumber: pp.SequenceNumber,
		View:           pp.View,
		Digest:         pp.Digest.Hash,
		Request:        pp.Request,
		Status:         StatusPrePrepared,
		PrePrepareMsg:  pp,
		PrepareVotes:   make(map[int]*pb.PrepareRequest),
		CommitVotes:    make(map[int]*pb.CommitRequest),
	}
}

func (n *Node) SubmitRequest(ctx context.Context, req *pb.ClientRequest) (*pb.ClientReply, error) {
	tx := req.Transaction
	if tx == nil {
		return &pb.ClientReply{Result: "failed: missing transaction"}, nil
	}

	// --- Read-Only Path ---
	if isReadOnly(tx) {
		if n.AttackModes["crash"] {
			log.Printf("Node %d [ATTACK]: Crashing. *NOT* answering read-only request from %s (ts=%d).", n.ID, req.ClientId, req.Timestamp)
			return n.withholdReply(ctx), nil
		}

		n.mu.Lock()
		log.Printf("Node %d received Read-Only request from %s (ts=%d). Executing immediately.", n.ID, req.ClientId, req.Timestamp)

		// Reads never write: an unknown account just reports the initial balance.
		result := "Balance: 10"
		if val, ok := n.DB[tx.Sender]; ok {
			result = fmt.Sprintf("Balance: %d", val)
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
	reqKey := requestKey(req)
	n.mu.Lock()

	// Already executed (late copy or client retransmission): answer from the record.
	if rec, ok := n.executedReqs[reqKey]; ok {
		n.mu.Unlock()
		log.Printf("Node %d: %s was already executed. Re-sending the reply.", n.ID, reqKey)
		return n.clientReply(ctx, req, rec)
	}

	if _, ok := n.pendingRequests[reqKey]; ok {
		log.Printf("Node %d received duplicate SubmitRequest for %s. Waiting for execution.", n.ID, reqKey)
	} else {
		log.Printf("Node %d received Read-Write request from client %s (ts=%d)", n.ID, req.ClientId, req.Timestamp)
		n.arrivals++
		n.pendingRequests[reqKey] = &pendingRequest{req: req, arrival: n.arrivals}
	}
	done, ok := n.execWaiters[reqKey]
	if !ok {
		done = make(chan struct{})
		n.execWaiters[reqKey] = done
	}

	if n.getPrimaryID(n.View) == n.ID && n.State == StateNormal {
		// --- Attack Logic: Timing ---
		if n.AttackModes["time"] {
			log.Printf("Node %d (Primary) [ATTACK]: Timing attack. Delaying %s for %v...", n.ID, reqKey, TimingAttackDelay)
			n.mu.Unlock() // Unlock while sleeping
			time.Sleep(TimingAttackDelay)
			n.mu.Lock() // Re-lock
		}
		// --- End Attack Logic ---
		n.proposePending()
	} else {
		// --- Backup Logic ---
		// NO FORWARDING. The client broadcasts to every replica; wait for consensus.
		// If a view change makes this node primary, it proposes the request then.
		log.Printf("Node %d (Backup) received %s. Awaiting consensus.", n.ID, reqKey)
	}
	n.mu.Unlock()

	// --- Wait for Execution ---
	waitCtx, cancel := context.WithTimeout(ctx, MaxClientWait)
	defer cancel()
	select {
	case <-done:
		n.mu.Lock()
		rec := n.executedReqs[reqKey]
		n.mu.Unlock()
		return n.clientReply(ctx, req, rec)

	case <-waitCtx.Done(): // Client cancelled, timed out, or will retransmit
		log.Printf("Node %d: Client request context done for %s before execution", n.ID, reqKey)
		return &pb.ClientReply{Result: "failed: client timeout"}, nil
	}
}

// clientReply signs the reply for an executed request.
// Implements the "Crash" attack for replies.
func (n *Node) clientReply(ctx context.Context, req *pb.ClientRequest, rec execRecord) (*pb.ClientReply, error) {
	reqKey := requestKey(req)

	// --- Attack Logic: Crash (Reply) ---
	// PDF: "does not send reply messages back to clients"
	if n.AttackModes["crash"] {
		log.Printf("Node %d [ATTACK]: Crashing. *NOT* sending reply for %s to client.", n.ID, reqKey)
		return n.withholdReply(ctx), nil
	}

	replyCoreData, err := clientReplyDataForSig(rec.view, req.Timestamp, req.ClientId, int32(n.ID), rec.result)
	if err != nil {
		log.Printf("Node %d: Failed to serialize reply for signing: %v", n.ID, err)
		return &pb.ClientReply{Result: "failed: internal error"}, nil
	}
	signature, err := n.sign(replyCoreData)
	if err != nil {
		log.Printf("Node %d: Failed to sign reply for %s: %v", n.ID, reqKey, err)
		return &pb.ClientReply{Result: "failed: internal error"}, nil
	}

	log.Printf("Node %d sending final reply for %s: %s", n.ID, reqKey, rec.result)
	return &pb.ClientReply{
		View:      rec.view,
		Timestamp: req.Timestamp,
		ClientId:  req.ClientId,
		ReplicaId: int32(n.ID),
		Result:    rec.result,
		Signature: signature,
	}, nil
}

// withholdReply blocks until the client gives up; a crashed replica never answers.
func (n *Node) withholdReply(ctx context.Context) *pb.ClientReply {
	select {
	case <-ctx.Done():
	case <-time.After(MaxClientWait):
	}
	return &pb.ClientReply{Result: "failed: no reply"}
}

// proposePending assigns sequence numbers to the client requests this primary has
// received but not yet proposed in the current view, oldest first, while they fit
// in the watermark window. Requests that do not fit are proposed by attemptExecution
// as the window slides.
// MUST be called with the lock held.
func (n *Node) proposePending() {
	if n.getPrimaryID(n.View) != n.ID || n.State != StateNormal {
		return
	}

	queue := make([]*pendingRequest, 0, len(n.pendingRequests))
	for key, p := range n.pendingRequests {
		if v, ok := n.proposedInView[key]; ok && v == n.View {
			continue
		}
		queue = append(queue, p)
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].arrival < queue[j].arrival })

	seqsPerRequest := int64(1)
	if n.AttackModes["equivocation"] {
		seqsPerRequest = 2
	}
	for i, p := range queue {
		if n.SeqNum+seqsPerRequest > n.LastExecuted+MaxInFlight {
			log.Printf("Node %d (Primary): %d request(s) waiting for the watermark window (lastExec=%d, seq=%d)", n.ID, len(queue)-i, n.LastExecuted, n.SeqNum)
			return
		}
		n.propose(p.req)
	}
}

// propose assigns the next sequence number to req and broadcasts the PrePrepare.
// Implements the "Equivocation" attack.
// MUST be called with the lock held.
func (n *Node) propose(req *pb.ClientRequest) {
	reqKey := requestKey(req)
	currentView := n.View

	d, err := digest(req)
	if err != nil {
		log.Printf("Node %d (Primary): Failed to calculate digest: %v", n.ID, err)
		return
	}
	n.proposedInView[reqKey] = currentView

	n.SeqNum++
	seqNum := n.SeqNum

	// --- Attack Logic: Equivocation ---
	if n.AttackModes["equivocation"] {
		log.Printf("Node %d (Primary) [ATTACK]: Executing Equivocation for seq %d", n.ID, seqNum)

		// Burn the next sequence number for the conflicting copy
		n.SeqNum++
		equivSeqNum := n.SeqNum

		// PrePrepare for (seq, req) and the conflicting one for (seq+1, req)
		prePrepareMsg1, err1 := n.createSignedPrePrepare(currentView, seqNum, d, req)
		prePrepareMsg2, err2 := n.createSignedPrePrepare(currentView, equivSeqNum, d, req)
		if err1 != nil || err2 != nil {
			log.Printf("Node %d (Primary): Failed to sign PrePrepares: %v %v", n.ID, err1, err2)
			return
		}
		n.logPrePrepare(prePrepareMsg1)
		n.logPrePrepare(prePrepareMsg2)

		log.Printf("Node %d [ATTACK]: Sending conflicting messages to targets %v", n.ID, n.equivocationTargets)
		for peerID := range n.NodeAddrs {
			if peerID == n.ID {
				continue
			}
			msgToSend := prePrepareMsg1
			if n.equivocationTargets[peerID] {
				// peerID is in the equivocation target set: send the conflicting message
				msgToSend = prePrepareMsg2
			}
			go n.sendToPeer(peerID, msgToSend, "PrePrepare")
		}
		log.Printf("Node %d [ATTACK]: Sent seq %d to targets %v and seq %d to everyone else", n.ID, equivSeqNum, n.equivocationTargets, seqNum)
		return
	}
	// --- End Attack Logic ---

	prePrepareMsg, err := n.createSignedPrePrepare(currentView, seqNum, d, req)
	if err != nil {
		log.Printf("Node %d (Primary): Failed to sign PrePrepare: %v", n.ID, err)
		return
	}
	n.logPrePrepare(prePrepareMsg)
	log.Printf("Node %d (Primary) assigned seq=%d to request %s", n.ID, seqNum, reqKey)

	// Broadcast PrePrepare to all backups
	for peerID := range n.NodeAddrs {
		if peerID == n.ID {
			continue
		}
		// Use the generic send helper which checks for In-dark
		go n.sendToPeer(peerID, prePrepareMsg, "PrePrepare")
	}
}

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

func (n *Node) sendToPeer(peerID int, msg interface{}, msgType string) {
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

// startRequestTimer (re)starts the backup's timer for seq. If the request has not
// executed when it fires, the backup suspects the primary and starts a view change.
// MUST be called with the lock held.
func (n *Node) startRequestTimer(seq int64, view int32) {
	if timer, ok := n.requestTimers[seq]; ok {
		timer.Stop()
	}
	n.requestTimers[seq] = time.AfterFunc(RequestTimeout, func() {
		n.handleRequestTimeout(seq, view)
	})
}

func (n *Node) SendPrePrepare(ctx context.Context, req *pb.PrePrepareRequest) (*pb.Ack, error) {
	if req.Digest == nil || req.Request == nil {
		return &pb.Ack{Success: false, ErrorMessage: "malformed PrePrepare"}, nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	primaryID := n.getPrimaryID(req.View)
	prePrepareCoreData, err := prePrepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash)
	if err != nil {
		log.Printf("Node %d: Failed to serialize PrePrepare for verification: %v", n.ID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal error"}, nil
	}
	if !n.verify(primaryID, prePrepareCoreData, req.Signature) {
		log.Printf("Node %d: Invalid signature on PrePrepare from node %d", n.ID, primaryID)
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}
	d, err := digest(req.Request)
	if err != nil || !bytes.Equal(d, req.Digest.Hash) {
		log.Printf("Node %d: Digest mismatch for PrePrepare seq %d view %d!", n.ID, req.SequenceNumber, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "digest mismatch"}, nil
	}

	// --- Attack Logic: Crash (as Backup) ---
	if n.AttackModes["crash"] {
		log.Printf("Node %d (Backup) [ATTACK]: Crashing. Received PrePrepare for seq %d but will not send Prepare.", n.ID, req.SequenceNumber)
		if existing, ok := n.MessageLog[req.SequenceNumber]; !ok || existing.View < req.View {
			n.MessageLog[req.SequenceNumber] = newLogEntry(req)
		}
		return &pb.Ack{Success: true}, nil // Lie and say we're fine
	}
	// --- End Attack Logic ---

	log.Printf("Node %d received PrePrepare from primary for seq=%d view=%d", n.ID, req.SequenceNumber, req.View)

	if req.View < n.View {
		log.Printf("Node %d: Received PrePrepare for old view %d (current %d)", n.ID, req.View, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	if req.SequenceNumber <= n.Watermarks.Low || req.SequenceNumber > n.Watermarks.High {
		log.Printf("Node %d: PrePrepare seq num %d outside watermarks [%d, %d]", n.ID, req.SequenceNumber, n.Watermarks.Low, n.Watermarks.High)
		return &pb.Ack{Success: false, ErrorMessage: "sequence number out of bounds"}, nil
	}

	entry, ok := n.MessageLog[req.SequenceNumber]
	switch {
	case !ok || entry.View < req.View:
		fresh := newLogEntry(req)
		if ok {
			fresh.PreparedCert = entry.PreparedCert // keep the older certificate for view changes
		}
		n.MessageLog[req.SequenceNumber] = fresh
		entry = fresh

	case entry.PrePrepareMsg != nil && !bytes.Equal(entry.Digest, req.Digest.Hash):
		// Two different requests signed by the primary for the same (view, seq).
		log.Printf("Node %d: Conflicting PrePrepare for seq %d view %d!", n.ID, req.SequenceNumber, req.View)
		log.Printf("Node %d: Equivocation detected! Triggering view change.", n.ID)
		n.startViewChange(n.View + 1)
		return &pb.Ack{Success: false, ErrorMessage: "conflicting digest for same seq/view"}, nil

	case !bytes.Equal(entry.Digest, req.Digest.Hash):
		// We already hold a commit certificate for a different request at this (view, seq).
		log.Printf("Node %d: PrePrepare for seq %d view %d conflicts with the commit certificate. Ignoring.", n.ID, req.SequenceNumber, req.View)
		return &pb.Ack{Success: false, ErrorMessage: "conflicts with commit certificate"}, nil

	default:
		// Same view, same request. The FullPrepare or FullCommit for this seq may have
		// overtaken this PrePrepare: fill in what is missing, never move the entry back.
		if entry.Request == nil {
			entry.Request = req.Request
		}
		if entry.PrePrepareMsg == nil {
			entry.PrePrepareMsg = req
		}
		if entry.Status == StatusNone {
			entry.Status = StatusPrePrepared
		}
		if entry.FullCommitRx && (entry.Status == StatusPrePrepared || entry.Status == StatusPrepared) {
			entry.Status = StatusCommitted
			n.attemptExecution()
		}
	}

	log.Printf("Node %d PrePrepared seq=%d view=%d (status %s)", n.ID, req.SequenceNumber, req.View, entry.Status)

	if entry.Status != StatusPrePrepared {
		// Already prepared or committed through the FullPrepare/FullCommit path.
		return &pb.Ack{Success: true}, nil
	}

	// As a backup, if we get a PrePrepare, we start a timer.
	n.startRequestTimer(req.SequenceNumber, req.View)
	log.Printf("Node %d (Backup) started timer for seq %d", n.ID, req.SequenceNumber)

	prepareCoreData, err := prepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash, int32(n.ID))
	if err != nil {
		log.Printf("Node %d: Failed to serialize Prepare for signing: %v", n.ID, err)
		return &pb.Ack{Success: true}, nil // Acknowledged PrePrepare, but failed to send Prepare
	}

	signature, err := n.sign(prepareCoreData)
	if err != nil {
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

	go n.sendToPeer(primaryID, prepareMsg, "Prepare")

	return &pb.Ack{Success: true}, nil
}

func (n *Node) SendPrepare(ctx context.Context, req *pb.PrepareRequest) (*pb.Ack, error) {
	if req.Digest == nil {
		return &pb.Ack{Success: false, ErrorMessage: "malformed Prepare"}, nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

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
	if int(req.ReplicaId) == n.ID {
		// The primary's PrePrepare already counts as its vote.
		return &pb.Ack{Success: false, ErrorMessage: "primary does not vote with Prepare"}, nil
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

	if len(entry.PrepareVotes) >= (n.QuorumSize-1) && entry.Status == StatusPrePrepared {
		proofs := make([]*pb.PrepareRequest, 0, len(entry.PrepareVotes))
		for _, proof := range entry.PrepareVotes {
			proofs = append(proofs, proof)
		}
		entry.Status = StatusPrepared
		entry.PreparedCert = &pb.PProof{PrePrepareReq: entry.PrePrepareMsg, PrepareReqs: proofs}

		if n.AttackModes["crash"] {
			log.Printf("Node %d (Primary) [ATTACK]: Crashing. Reached Prepare quorum for seq %d but will not send FullPrepare.", n.ID, req.SequenceNumber)
			return &pb.Ack{Success: true}, nil // Lie and say we're fine
		}

		log.Printf("Node %d (Primary) has prepared seq=%d. Broadcasting FullPrepare.", n.ID, req.SequenceNumber)

		// --- Broadcast FullPrepare ---
		fullPrepareMsg := &pb.FullPrepareRequest{
			PrePrepareProof: entry.PrePrepareMsg,
			PrepareProofs:   proofs,
		}
		for peerID := range n.NodeAddrs {
			if peerID == n.ID {
				continue
			} // Don't send to self

			// Use generic helper (checks for in-dark)
			go n.sendToPeer(peerID, fullPrepareMsg, "FullPrepare")
		}
	}

	return &pb.Ack{Success: true}, nil
}

// SendFullPrepare is called by the primary, handled by backups.
// Implements "Crash" attack
func (n *Node) SendFullPrepare(ctx context.Context, req *pb.FullPrepareRequest) (*pb.Ack, error) {
	if req.PrePrepareProof == nil || req.PrePrepareProof.Digest == nil || req.PrePrepareProof.Request == nil {
		log.Printf("Node %d: Received FullPrepare with missing PrePrepare proof", n.ID)
		return &pb.Ack{Success: false, ErrorMessage: "missing PrePrepare proof"}, nil
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	// --- Check if we're in a view change ---
	if n.State == StateViewChanging && req.PrePrepareProof.View < n.View {
		log.Printf("Node %d: In ViewChanging state, ignoring old FullPrepare for view %d", n.ID, req.PrePrepareProof.View)
		return &pb.Ack{Success: false, ErrorMessage: "node in view change"}, nil
	}

	pp := req.PrePrepareProof
	v := pp.View
	n_seq := pp.SequenceNumber
	d_hash := pp.Digest.Hash

	// --- Attack Logic: Crash (as Backup) ---
	// PDF: (a) fails to send any prepare messages [here, Commit]
	if n.AttackModes["crash"] {
		log.Printf("Node %d (Backup) [ATTACK]: Crashing. Received FullPrepare for seq %d but will not send Commit.", n.ID, n_seq)
		return &pb.Ack{Success: true}, nil // Lie and say we're fine
	}
	// --- End Attack Logic ---

	primaryID := n.getPrimaryID(v)
	log.Printf("Node %d (Backup) received FullPrepare: seq=%d view=%d", n.ID, n_seq, v)

	// --- Full Validation ---
	if v < n.View {
		log.Printf("Node %d: Received FullPrepare for old view %d (current %d)", n.ID, v, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	prePrepareCoreData, err := prePrepareDataForSig(v, n_seq, d_hash)
	if err != nil {
		log.Printf("Node %d: Failed to serialize PrePrepare for verification: %v", n.ID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
	}
	if !n.verify(primaryID, prePrepareCoreData, pp.Signature) {
		log.Printf("Node %d: Invalid signature on PrePrepareProof from primary %d", n.ID, primaryID)
		return &pb.Ack{Success: false, ErrorMessage: "invalid PrePrepare signature"}, nil
	}
	if d, err := digest(pp.Request); err != nil || !bytes.Equal(d, d_hash) {
		log.Printf("Node %d: Digest mismatch for request in FullPrepare seq %d!", n.ID, n_seq)
		return &pb.Ack{Success: false, ErrorMessage: "digest mismatch on request"}, nil
	}

	if len(req.PrepareProofs) < (n.QuorumSize - 1) { // Need 2f=4 proofs
		log.Printf("Node %d: Received FullPrepare with insufficient proofs (%d)", n.ID, len(req.PrepareProofs))
		return &pb.Ack{Success: false, ErrorMessage: "insufficient prepare proofs"}, nil
	}

	prepareSigners := make(map[int]bool)
	for _, prep := range req.PrepareProofs {
		if prep.Digest == nil || prep.View != v || prep.SequenceNumber != n_seq || !bytes.Equal(prep.Digest.Hash, d_hash) {
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
	switch {
	case !ok || entry.View < v:
		fresh := newLogEntry(pp)
		if ok {
			fresh.PreparedCert = entry.PreparedCert // keep the older certificate for view changes
		}
		n.MessageLog[n_seq] = fresh
		entry = fresh
	case !bytes.Equal(entry.Digest, d_hash):
		log.Printf("Node %d: FullPrepare for seq %d view %d conflicts with the logged request. Ignoring.", n.ID, n_seq, v)
		return &pb.Ack{Success: false, ErrorMessage: "conflicting request for seq/view"}, nil
	default:
		// Same view and request; the PrePrepare may not have arrived yet.
		if entry.Request == nil {
			entry.Request = pp.Request
		}
		if entry.PrePrepareMsg == nil {
			entry.PrePrepareMsg = pp
		}
	}

	if entry.Status == StatusNone || entry.Status == StatusPrePrepared {
		entry.Status = StatusPrepared // We have proof, so mark prepared
	}
	entry.FullPrepareRx = true
	for _, p := range req.PrepareProofs {
		entry.PrepareVotes[int(p.ReplicaId)] = p
	}
	entry.PreparedCert = &pb.PProof{PrePrepareReq: pp, PrepareReqs: req.PrepareProofs}

	// The PrePrepare may have been lost or overtaken; make sure a timer guards this seq.
	if _, hasTimer := n.requestTimers[n_seq]; !hasTimer && n_seq > n.LastExecuted {
		n.startRequestTimer(n_seq, v)
	}

	log.Printf("Node %d (Backup) has prepared seq=%d.", n.ID, n_seq)

	if entry.FullCommitRx && entry.Status == StatusPrepared {
		entry.Status = StatusCommitted
		n.attemptExecution()
	}

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
		Digest:         pp.Digest,
		ReplicaId:      int32(n.ID),
		Signature:      signature,
	}

	// Use generic helper (checks for in-dark)
	go n.sendToPeer(primaryID, commitMsg, "Commit")

	return &pb.Ack{Success: true}, nil
}

// SendCommit is called by backups, handled by the primary.
// Implements "Crash" attack
func (n *Node) SendCommit(ctx context.Context, req *pb.CommitRequest) (*pb.Ack, error) {
	if req.Digest == nil {
		return &pb.Ack{Success: false, ErrorMessage: "malformed Commit"}, nil
	}

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
	if int(req.ReplicaId) == n.ID {
		return &pb.Ack{Success: false, ErrorMessage: "primary does not vote with Commit"}, nil
	}
	entry, ok := n.MessageLog[req.SequenceNumber]
	if !ok || entry.View != req.View {
		return &pb.Ack{Success: false, ErrorMessage: "no matching log entry"}, nil
	}
	// Must be at least prepared to accept commits
	if entry.Status == StatusNone || entry.Status == StatusPrePrepared {
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

		for peerID := range n.NodeAddrs {
			if peerID == n.ID {
				continue
			}
			// Use generic helper (checks for in-dark)
			go n.sendToPeer(peerID, fullCommitMsg, "FullCommit")
		}
	}

	return &pb.Ack{Success: true}, nil
}

// SendFullCommit is called by the primary, handled by backups.
func (n *Node) SendFullCommit(ctx context.Context, req *pb.FullCommitRequest) (*pb.Ack, error) {
	if req.Digest == nil {
		return &pb.Ack{Success: false, ErrorMessage: "malformed FullCommit"}, nil
	}

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
		if com.Digest == nil || com.View != v || com.SequenceNumber != n_seq || !bytes.Equal(com.Digest.Hash, d_hash) {
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
	if ok && entry.View < v && entry.Request != nil && bytes.Equal(entry.Digest, d_hash) {
		// Same request re-proposed in a newer view; the certificate covers it.
		entry.View = v
	}
	if !ok || entry.View < v || entry.Request == nil {
		// The FullCommit overtook the PrePrepare/FullPrepare. Remember the certificate
		// and commit as soon as the request itself arrives.
		log.Printf("Node %d: FullCommit for seq %d arrived before the request. Holding it.", n.ID, n_seq)
		if !ok || entry.View < v {
			placeholder := &InternalLogEntry{
				SequenceNumber: n_seq,
				View:           v,
				Digest:         d_hash,
				Status:         StatusNone,
				PrepareVotes:   make(map[int]*pb.PrepareRequest),
				CommitVotes:    make(map[int]*pb.CommitRequest),
			}
			if ok {
				placeholder.PreparedCert = entry.PreparedCert
			}
			n.MessageLog[n_seq] = placeholder
			entry = placeholder
		}
		entry.FullCommitRx = true
		return &pb.Ack{Success: true}, nil
	}
	if !bytes.Equal(entry.Digest, d_hash) {
		log.Printf("Node %d: FullCommit digest for seq %d does not match the logged request", n.ID, n_seq)
		return &pb.Ack{Success: false, ErrorMessage: "digest mismatch"}, nil
	}

	// 2f matching Commits plus the primary's are proof the request committed, even if
	// our own FullPrepare has not arrived yet.
	if entry.Status != StatusCommitted && entry.Status != StatusExecuted {
		entry.Status = StatusCommitted
	}
	entry.FullCommitRx = true

	log.Printf("Node %d (Backup) has committed seq=%d.", n.ID, n_seq)

	if n_seq <= n.LastExecuted {
		// Re-proposal of a request we already executed; nothing left to wait for.
		if timer, ok := n.requestTimers[n_seq]; ok {
			timer.Stop()
			delete(n.requestTimers, n_seq)
		}
	}

	// Execute request (must be in order)
	n.attemptExecution()

	return &pb.Ack{Success: true}, nil
}

// applyTransaction executes one client operation against the DB and returns the result.
// MUST be called with the lock held.
func (n *Node) applyTransaction(tx *pb.Transaction) string {
	if tx == nil {
		return "success"
	}

	// --- Handle Read Requests (read-only, or re-sent through consensus) ---
	if isReadOnly(tx) || isConsensusRead(tx) {
		if val, ok := n.DB[tx.Sender]; ok {
			return fmt.Sprintf("Balance: %d", val)
		}
		n.DB[tx.Sender] = 10 // Initialize if not present
		return "Balance: 10"
	}

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
		return "success"
	}
	return "failed: insufficient funds"
}

// attemptExecution is a helper function to execute all possible
// requests in strict sequence order.
// Stops timers and wakes up the client handlers waiting for a reply.
// MUST be called with the lock held.
func (n *Node) attemptExecution() {
	executedAny := false
	for {
		seqToExec := n.LastExecuted + 1
		entry, ok := n.MessageLog[seqToExec]
		if !ok {
			// We haven't even heard of the next request, so we must stop.
			break
		}

		if entry.Status != StatusCommitted || entry.Request == nil {
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
		req := entry.Request
		if req.ClientId != NoOpClientID {
			reqKey := requestKey(req)
			if rec, done := n.executedReqs[reqKey]; done {
				// The same request was already executed at another sequence number
				// (e.g. an equivocating primary assigned it twice). Never apply it twice.
				result = rec.result
				log.Printf("Node %d: seq=%d repeats already-executed request %s. Not applying it again.", n.ID, seqToExec, reqKey)
			} else {
				result = n.applyTransaction(req.Transaction)
				n.executedReqs[reqKey] = execRecord{result: result, view: entry.View}
			}

			// Wake up every SubmitRequest handler waiting on this request
			delete(n.pendingRequests, reqKey)
			delete(n.proposedInView, reqKey)
			if done, ok := n.execWaiters[reqKey]; ok {
				close(done)
				delete(n.execWaiters, reqKey)
			}
		}
		// If it's a "no-op", result just stays "success"

		entry.Status = StatusExecuted
		n.LastExecuted = seqToExec
		// No stable checkpoints yet, so slide the window with execution.
		n.Watermarks.High = n.LastExecuted + WatermarkRange
		executedAny = true
		log.Printf("Node %d EXECUTED seq=%d with result: %s", n.ID, seqToExec, result)

		// TODO: Trigger checkpointing if n.LastExecuted % CheckpointPeriod == 0

		// Loop again to try executing the *next* sequence number
	}

	if executedAny {
		// The window moved; a primary can now propose requests that were waiting.
		n.proposePending()
	}
}

// handleRequestTimeout is called when a backup's timer fires
func (n *Node) handleRequestTimeout(seqNum int64, view int32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// 1. Check if the request was already executed or the view has changed
	if seqNum <= n.LastExecuted {
		log.Printf("Node %d: Timer fired for seq %d, but it was already executed. Ignoring.", n.ID, seqNum)
		delete(n.requestTimers, seqNum)
		return
	}

	if n.View != view {
		log.Printf("Node %d: Timer fired for seq %d (view %d), but we are in view %d. Ignoring.", n.ID, seqNum, view, n.View)
		delete(n.requestTimers, seqNum)
		return
	}

	// 2. If we are already changing views, the view-change timer is in charge
	if n.State == StateViewChanging {
		log.Printf("Node %d: Timer fired for seq %d, but already changing to view %d.", n.ID, seqNum, n.View)
		return
	}

	// 3. Trigger a View Change
	log.Printf("Node %d: TIMER EXPIRED for seq %d (view %d). Leader is faulty! TRIGGERING VIEW CHANGE.", n.ID, seqNum, view)
	delete(n.requestTimers, seqNum)

	n.startViewChange(n.View + 1)
}

// startViewChange moves this replica to view `target` and broadcasts its VIEW-CHANGE.
// MUST be called with the lock held.
func (n *Node) startViewChange(target int32) {
	if target <= n.View {
		return // already in, or changing to, this view or a later one
	}

	n.State = StateViewChanging
	n.View = target // Tentatively update view to stop processing old messages
	log.Printf("Node %d: Entering state %s for view %d", n.ID, n.State, target)

	// Clear out any old request timers
	for seq, timer := range n.requestTimers {
		timer.Stop()
		delete(n.requestTimers, seq)
	}
	if n.viewTimer != nil {
		n.viewTimer.Stop()
	}

	// --- 1. Build the P-set (Prepared Proofs) ---
	// Every request this replica has prepared (including ones that already committed
	// or executed) above the low watermark. Checkpointing is a bonus, so min-s is 0.
	preparedProofs := make([]*pb.PProof, 0)
	seqs := make([]int64, 0, len(n.MessageLog))
	for seq, entry := range n.MessageLog {
		if entry.PreparedCert != nil && seq > n.Watermarks.Low {
			seqs = append(seqs, seq)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, seq := range seqs {
		log.Printf("Node %d: Adding seq %d to P-set for view change", n.ID, seq)
		preparedProofs = append(preparedProofs, n.MessageLog[seq].PreparedCert)
	}

	// --- 2. Create and Sign the ViewChangeRequest ---
	// As per PDF, checkpoint cert is not needed and min-s=0.
	vcRequest := &pb.ViewChangeRequest{
		NewView:          target,
		CheckpointSeqNum: n.Watermarks.Low, // No checkpoints
		CheckpointProof:  nil,              // No checkpoints
		PreparedProof:    preparedProofs,
		ReplicaId:        int32(n.ID),
	}

	// The signature is over <VIEW-CHANGE, v+1, n, C, P, i>
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
	if _, ok := n.viewChangeVotes[target]; !ok {
		n.viewChangeVotes[target] = make(map[int]*pb.ViewChangeRequest)
	}
	n.viewChangeVotes[target][n.ID] = vcRequest
	n.viewChangeHistory = append(n.viewChangeHistory, vcRequest)

	log.Printf("Node %d: Broadcasting ViewChangeRequest for view %d...", n.ID, target)
	for peerID := range n.NodeAddrs {
		if peerID == n.ID {
			continue
		}
		go n.sendToPeer(peerID, vcRequest, "ViewChange")
	}

	// --- 4. View-change timer ---
	// If no NewView installs this view in time, the new primary is faulty too:
	// move on to the next view, waiting twice as long each time.
	attempts := n.vcAttempts
	if attempts > 3 {
		attempts = 3
	}
	timeout := ViewChangeTimeout * time.Duration(1<<attempts)
	n.viewTimer = time.AfterFunc(timeout, func() {
		n.handleViewChangeTimeout(target)
	})

	// We may already hold a quorum for this view (we joined late).
	n.checkNewView(target)
}

// handleViewChangeTimeout fires when a view change did not complete in time.
func (n *Node) handleViewChangeTimeout(target int32) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.State != StateViewChanging || n.View != target {
		return // the view was installed, or we already moved on
	}
	log.Printf("Node %d: VIEW-CHANGE TIMER EXPIRED for view %d (no NewView from primary %d). Moving to view %d.", n.ID, target, n.getPrimaryID(target), target+1)
	n.vcAttempts++
	n.startViewChange(target + 1)
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

// newViewDataForSig serializes the core NewView fields for signing/verification
func newViewDataForSig(v int32, oSetSize int) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(struct {
		V int32
		O int
	}{v, oSetSize}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// validViewChange checks the signature of a ViewChange message.
func (n *Node) validViewChange(vc *pb.ViewChangeRequest) bool {
	if vc == nil || vc.ReplicaId < 0 || int(vc.ReplicaId) >= n.N {
		return false
	}
	vcData, err := viewChangeDataForSig(vc)
	if err != nil {
		return false
	}
	return n.verify(int(vc.ReplicaId), vcData, vc.Signature)
}

// validPreparedProof checks a P-set entry: the primary's signed PrePrepare plus 2f
// matching, correctly signed Prepares from distinct backups.
func (n *Node) validPreparedProof(p *pb.PProof) bool {
	if p == nil || p.PrePrepareReq == nil || p.PrePrepareReq.Digest == nil || p.PrePrepareReq.Request == nil {
		return false
	}
	pp := p.PrePrepareReq
	ppData, err := prePrepareDataForSig(pp.View, pp.SequenceNumber, pp.Digest.Hash)
	if err != nil || !n.verify(n.getPrimaryID(pp.View), ppData, pp.Signature) {
		return false
	}
	if d, err := digest(pp.Request); err != nil || !bytes.Equal(d, pp.Digest.Hash) {
		return false
	}
	signers := make(map[int]bool)
	for _, prep := range p.PrepareReqs {
		if prep == nil || prep.Digest == nil || prep.View != pp.View || prep.SequenceNumber != pp.SequenceNumber || !bytes.Equal(prep.Digest.Hash, pp.Digest.Hash) {
			continue
		}
		data, err := prepareDataForSig(prep.View, prep.SequenceNumber, prep.Digest.Hash, prep.ReplicaId)
		if err != nil || !n.verify(int(prep.ReplicaId), data, prep.Signature) {
			continue
		}
		signers[int(prep.ReplicaId)] = true
	}
	return len(signers) >= n.QuorumSize-1
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
	if newView < n.View || (newView == n.View && n.State == StateNormal) {
		log.Printf("Node %d: Received ViewChange for view %d, but view %d is already installed. Ignoring.", n.ID, newView, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	// Verify signature
	if !n.validViewChange(req) {
		log.Printf("Node %d: Received ViewChange from %d with INVALID signature. Ignoring.", n.ID, senderID)
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}

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
	n.viewChangeHistory = append(n.viewChangeHistory, req)
	log.Printf("Node %d: Stored ViewChange vote from %d for view %d. Total votes: %d/%d", n.ID, senderID, newView, len(n.viewChangeVotes[newView]), n.QuorumSize)

	// --- 3. Join the view change ---
	// f+1 replicas asking for a higher view include at least one correct replica,
	// so this node joins even if its own timers have not fired.
	if newView > n.View && len(n.viewChangeVotes[newView]) >= n.F+1 {
		log.Printf("Node %d: f+1 ViewChange messages for view %d, joining the view change.", n.ID, newView)
		n.startViewChange(newView)
	}

	// --- 4. If WE are the new Primary and have 2f+1 votes, send NewView ---
	n.checkNewView(newView)

	return &pb.Ack{Success: true}, nil
}

// checkNewView sends the NewView once the new primary holds 2f+1 ViewChange messages.
// MUST be called with the lock held.
func (n *Node) checkNewView(v int32) {
	if n.State != StateViewChanging || n.View != v {
		return
	}
	if len(n.viewChangeVotes[v]) < n.QuorumSize {
		return
	}
	if n.getPrimaryID(v) != n.ID || n.newViewSent[v] {
		return
	}
	log.Printf("Node %d: Achieved ViewChange quorum for view %d.", n.ID, v)

	if n.AttackModes["crash"] {
		log.Printf("Node %d (Primary) [ATTACK]: Crashing. Received ViewChange quorum but will not send NewView.", n.ID)
		n.newViewSent[v] = true
		return
	}

	log.Printf("Node %d: I AM THE NEW PRIMARY for view %d. Preparing NewView message.", n.ID, v)
	n.sendNewView(v)
}

// sendNewView is called by the new primary after a ViewChange quorum
func (n *Node) sendNewView(newView int32) {
	// This function must be called with the lock HELD
	log.Printf("Node %d (Primary): Constructing NewView for view %d", n.ID, newView)
	n.newViewSent[newView] = true

	// --- 1. Get the 2f+1 ViewChange messages (the V-set) ---
	vSet := n.viewChangeVotes[newView]
	senders := make([]int, 0, len(vSet))
	for id := range vSet {
		senders = append(senders, id)
	}
	sort.Ints(senders)
	vSetProofs := make([]*pb.ViewChangeRequest, 0, len(vSet))
	for _, id := range senders {
		vSetProofs = append(vSetProofs, vSet[id])
	}

	// --- 2. Determine min-s and max-s ---
	// min-s is the low watermark (0, no checkpoints)
	// max-s is the highest sequence number in any P-set
	minS := n.Watermarks.Low
	maxS := minS
	// We also need to find the "best" request for each sequence number
	// Key: seqNum, Value: the request with the highest view
	bestPSet := make(map[int64]*pb.PrePrepareRequest)

	for _, vcMsg := range vSetProofs {
		for _, pProof := range vcMsg.PreparedProof {
			if !n.validPreparedProof(pProof) {
				log.Printf("Node %d (Primary): Ignoring invalid P-set entry from %d", n.ID, vcMsg.ReplicaId)
				continue
			}
			seq := pProof.PrePrepareReq.SequenceNumber
			view := pProof.PrePrepareReq.View
			if seq <= minS {
				continue
			}

			if seq > maxS {
				maxS = seq
			}

			// If this proof is from a higher view, it's better
			if existing, ok := bestPSet[seq]; !ok || view > existing.View {
				bestPSet[seq] = pProof.PrePrepareReq
			}
		}
	}

	log.Printf("Node %d (Primary): Calculated minS=%d, maxS=%d for new view", n.ID, minS, maxS)

	// --- 3. Determine the O-set (new PrePrepares) ---
	oSet := make([]*pb.PrePrepareRequest, 0)

	for n_seq := minS + 1; n_seq <= maxS; n_seq++ {
		var newPrePrepare *pb.PrePrepareRequest
		var err error

		if bestReq, ok := bestPSet[n_seq]; ok {
			// --- Case 1: A request was prepared. Re-propose it. ---
			log.Printf("Node %d (Primary): Re-proposing seq %d for new view", n.ID, n_seq)
			// We must sign this new PrePrepare with the *new view*
			newPrePrepare, err = n.createSignedPrePrepare(newView, n_seq, bestReq.Digest.Hash, bestReq.Request)
		} else {
			// --- Case 2: No request was prepared. Propose a "no-op". ---
			log.Printf("Node %d (Primary): Proposing NO-OP for seq %d for new view", n.ID, n_seq)
			noOpReq := &pb.ClientRequest{ClientId: NoOpClientID}
			d, _ := digest(noOpReq)
			newPrePrepare, err = n.createSignedPrePrepare(newView, n_seq, d, noOpReq)
		}
		if err != nil {
			log.Printf("Node %d (Primary): Failed to sign O-set PrePrepare for seq %d: %v", n.ID, n_seq, err)
			return
		}
		oSet = append(oSet, newPrePrepare)
	}

	// --- 4. Create, sign, and broadcast the NewView message ---
	nvData, err := newViewDataForSig(newView, len(oSet))
	if err != nil {
		log.Printf("Node %d (Primary): Failed to encode NewView for signing: %v", n.ID, err)
		return
	}
	signature, err := n.sign(nvData)
	if err != nil {
		log.Printf("Node %d (Primary): Failed to sign NewView: %v", n.ID, err)
		return
	}
	newViewRequest := &pb.NewViewRequest{
		NewView:            newView,
		ViewChangeProof:    vSetProofs,
		ReproposedRequests: oSet,
		Signature:          signature,
	}

	// We are now in the new view
	n.installView(newView)

	// We also need to log these new PrePrepares ourselves
	for _, pp := range oSet {
		n.logPrePrepare(pp)
		if pp.Request.ClientId != NoOpClientID {
			n.proposedInView[requestKey(pp.Request)] = newView
		}
	}

	// Update our own SeqNum to be the new max
	n.SeqNum = maxS
	if n.LastExecuted > n.SeqNum {
		n.SeqNum = n.LastExecuted
	}

	log.Printf("Node %d (Primary): Broadcasting NewView for view %d", n.ID, newView)
	for peerID := range n.NodeAddrs {
		if peerID == n.ID {
			continue // we already processed it
		}
		go n.sendToPeer(peerID, newViewRequest, "NewView")
	}

	// Client requests that are still waiting and were not re-proposed above.
	n.proposePending()
}

// installView switches this replica into newView in the Normal state.
// MUST be called with the lock held.
func (n *Node) installView(newView int32) {
	n.State = StateNormal
	n.View = newView
	n.vcAttempts = 0
	if n.viewTimer != nil {
		n.viewTimer.Stop()
		n.viewTimer = nil
	}
	// Clear old timers
	for seq, timer := range n.requestTimers {
		timer.Stop()
		delete(n.requestTimers, seq)
	}
	// Clear view change votes for this and older views (history is kept for printview)
	for v := range n.viewChangeVotes {
		if v <= newView {
			delete(n.viewChangeVotes, v)
		}
	}
}

// SendNewView is called by the new primary, handled by backups
func (n *Node) SendNewView(ctx context.Context, req *pb.NewViewRequest) (*pb.Ack, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	newView := req.NewView
	senderID := n.getPrimaryID(newView)
	log.Printf("Node %d: Received NewView from primary %d for view %d", n.ID, senderID, newView)

	// --- 1. Validation ---
	if senderID == n.ID {
		return &pb.Ack{Success: true}, nil // our own NewView, already processed
	}
	if newView < n.View || (newView == n.View && n.State == StateNormal) {
		log.Printf("Node %d: Received NewView for view %d, but view %d is already installed. Ignoring.", n.ID, newView, n.View)
		return &pb.Ack{Success: false, ErrorMessage: "old view"}, nil
	}

	// Validate signature
	nvData, err := newViewDataForSig(newView, len(req.ReproposedRequests))
	if err != nil {
		log.Printf("Node %d: Failed to encode NewView for signature verification: %v", n.ID, err)
		return &pb.Ack{Success: false, ErrorMessage: "internal verify error"}, nil
	}
	if !n.verify(senderID, nvData, req.Signature) {
		log.Printf("Node %d: Received NewView from %d with INVALID signature. Ignoring.", n.ID, senderID)
		return &pb.Ack{Success: false, ErrorMessage: "invalid signature"}, nil
	}

	// Validate V-set: 2f+1 correctly signed ViewChange messages for this view from distinct replicas
	vcSenders := make(map[int]bool)
	for _, vc := range req.ViewChangeProof {
		if vc.NewView == newView && n.validViewChange(vc) {
			vcSenders[int(vc.ReplicaId)] = true
		}
	}
	if len(vcSenders) < n.QuorumSize {
		log.Printf("Node %d: Received NewView with insufficient V-set proofs (%d/%d). Ignoring.", n.ID, len(vcSenders), n.QuorumSize)
		return &pb.Ack{Success: false, ErrorMessage: "insufficient view change proofs"}, nil
	}

	// Validate O-set: every PrePrepare is for the new view, signed by its primary, with a matching digest
	for _, pp := range req.ReproposedRequests {
		if pp.Digest == nil || pp.Request == nil || pp.View != newView {
			return &pb.Ack{Success: false, ErrorMessage: "malformed O-set"}, nil
		}
		ppData, err := prePrepareDataForSig(pp.View, pp.SequenceNumber, pp.Digest.Hash)
		if err != nil || !n.verify(senderID, ppData, pp.Signature) {
			return &pb.Ack{Success: false, ErrorMessage: "invalid O-set signature"}, nil
		}
		if d, err := digest(pp.Request); err != nil || !bytes.Equal(d, pp.Digest.Hash) {
			return &pb.Ack{Success: false, ErrorMessage: "O-set digest mismatch"}, nil
		}
	}
	// TODO: Recompute the O-set from the V-set and compare

	// --- 2. State Transition ---
	n.installView(newView)
	log.Printf("Node %d (Backup): ACCEPTED NewView. Transitioned to view %d.", n.ID, newView)

	// --- 3. Process the O-set (new PrePrepares) ---
	oSet := append([]*pb.PrePrepareRequest(nil), req.ReproposedRequests...)
	sort.Slice(oSet, func(i, j int) bool { return oSet[i].SequenceNumber < oSet[j].SequenceNumber })
	maxSeq := n.LastExecuted
	for _, prePrepare := range oSet {
		n.logAndProcessPrePrepare(prePrepare)
		if prePrepare.SequenceNumber > maxSeq {
			maxSeq = prePrepare.SequenceNumber // Update our sequence number
		}
	}
	n.SeqNum = maxSeq

	return &pb.Ack{Success: true}, nil
}

// logAndProcessPrePrepare is a helper for backups to handle re-proposed requests.
// MUST be called with the lock held.
func (n *Node) logAndProcessPrePrepare(req *pb.PrePrepareRequest) {
	// 1. Log the new PrePrepare
	if !n.logPrePrepare(req) {
		log.Printf("Node %d (Backup): Failed to log re-proposed PrePrepare for seq %d", n.ID, req.SequenceNumber)
		return
	}

	// --- Attack Logic: Crash (as Backup) ---
	if n.AttackModes["crash"] {
		return // logs it, never sends Prepare
	}

	// 2. Start the request timer (unless we already executed this seq)
	if req.SequenceNumber > n.LastExecuted {
		n.startRequestTimer(req.SequenceNumber, req.View)
	}

	// 3. Send Prepare to the new primary
	prepareCoreData, err := prepareDataForSig(req.View, req.SequenceNumber, req.Digest.Hash, int32(n.ID))
	if err != nil {
		log.Printf("Node %d: Failed to serialize Prepare for signing: %v", n.ID, err)
		return
	}
	signature, err := n.sign(prepareCoreData)
	if err != nil {
		log.Printf("Node %d: Failed to sign Prepare for seq %d: %v", n.ID, req.SequenceNumber, err)
		return
	}

	prepareMsg := &pb.PrepareRequest{
		View:           req.View,
		SequenceNumber: req.SequenceNumber,
		Digest:         req.Digest,
		ReplicaId:      int32(n.ID),
		Signature:      signature,
	}

	go n.sendToPeer(n.getPrimaryID(req.View), prepareMsg, "Prepare")
}

// logPrePrepare is a helper to log a PrePrepare (used by primary and backups).
// A PrePrepare for an existing seq replaces the entry's request and resets its votes
// (used when a new primary re-proposes); the older prepared certificate is kept.
func (n *Node) logPrePrepare(req *pb.PrePrepareRequest) bool {
	// Assumes lock is HELD

	d, err := digest(req.Request)
	if err != nil || !bytes.Equal(d, req.Digest.Hash) {
		log.Printf("Node %d: Digest mismatch for logging PrePrepare seq %d!", n.ID, req.SequenceNumber)
		return false
	}

	entry, ok := n.MessageLog[req.SequenceNumber]
	if !ok {
		n.MessageLog[req.SequenceNumber] = newLogEntry(req)
		return true
	}

	if req.SequenceNumber <= n.LastExecuted && !bytes.Equal(entry.Digest, d) {
		log.Printf("Node %d: WARNING: PrePrepare for already-executed seq %d carries a different request", n.ID, req.SequenceNumber)
	}

	// Entry exists, replace it with the new view's proposal
	entry.View = req.View
	entry.Digest = d
	entry.Request = req.Request
	entry.Status = StatusPrePrepared
	entry.PrePrepareMsg = req
	entry.FullPrepareRx = false // Reset proofs
	entry.FullCommitRx = false
	entry.PrepareVotes = make(map[int]*pb.PrepareRequest)
	entry.CommitVotes = make(map[int]*pb.CommitRequest)
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

// displayStatus is the status shown by printlog/printstatus. Execution is strictly in
// order, so every seq up to LastExecuted is executed even if a later view re-proposed it.
// MUST be called with the lock held.
func (n *Node) displayStatus(entry *InternalLogEntry) string {
	if entry.SequenceNumber <= n.LastExecuted {
		return StatusExecuted
	}
	return entry.Status
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
		content := "UNKNOWN (awaiting request)"
		if entry.Request != nil {
			if entry.Request.ClientId == NoOpClientID {
				content = "NO-OP"
			} else if entry.Request.Transaction != nil {
				tx := entry.Request.Transaction
				// Differentiate between read-write and read-only
				if isReadOnly(tx) || isConsensusRead(tx) {
					content = fmt.Sprintf("(%s)", tx.Sender) // Read-Only
				} else {
					content = fmt.Sprintf("(%s, %s, %d)", tx.Sender, tx.Receiver, tx.Amount)
				}
			}
		}

		simpleLog = append(simpleLog, &pb.LogEntry{
			SequenceNumber: seq,
			Status:         n.displayStatus(entry),
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
			status = n.displayStatus(entry)
			if status == "" {
				status = "X"
			}
		}
	}

	// --- Build ViewChange history for PrintView ---
	viewChanges := make([]*pb.ViewChangeRequest, len(n.viewChangeHistory))
	copy(viewChanges, n.viewChangeHistory)

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
