package client

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "bft-DarkBrewww/proto"
)

const (
	// RequestTimeout is how long a client keeps retransmitting a read-write request
	// before giving up. It has to cover a view change whose first new primary is
	// also faulty (request timer + view-change timer on the replicas).
	RequestTimeout = 30 * time.Second
	// AttemptTimeout is how long one transmission to a replica waits for its reply.
	AttemptTimeout = 10 * time.Second
	// RetryBackoff is the pause before retransmitting to a replica.
	RetryBackoff = 500 * time.Millisecond
	// ReadOnlyTimeout bounds the read-only fast path before falling back to consensus.
	ReadOnlyTimeout = 3 * time.Second
)

type ClientOrchestrator struct {
	nodeAddrs map[int]string

	grpcClients map[int]pb.PbftNodeClient
	clientConn  map[int]*grpc.ClientConn

	f           int // Number of faults
	replyQuorum int // f+1 (for read-write)
	readQuorum  int // 2f+1 (for read-only)

	publicKeys map[int]*ecdsa.PublicKey

	clientStates map[string]*ClientState
	mu           sync.Mutex
}

type ClientState struct {
	ID         string
	Timestamp  int64
	LeaderHint int
}

func NewClientOrchestrator(addrs map[int]string, f int, pubKeys map[int]*ecdsa.PublicKey) *ClientOrchestrator {
	co := &ClientOrchestrator{
		nodeAddrs:    addrs,
		grpcClients:  make(map[int]pb.PbftNodeClient),
		clientConn:   make(map[int]*grpc.ClientConn),
		f:            f,
		replyQuorum:  f + 1,
		readQuorum:   2*f + 1,
		publicKeys:   pubKeys,
		clientStates: make(map[string]*ClientState),
	}

	for i := 0; i < 10; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		co.clientStates[clientID] = &ClientState{
			ID:         clientID,
			Timestamp:  0,
			LeaderHint: 0,
		}
	}
	return co
}

func (c *ClientOrchestrator) GetGrpcClient(peerID int) (pb.PbftNodeClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if client, ok := c.grpcClients[peerID]; ok {
		return client, nil
	}

	peerAddr, ok := c.nodeAddrs[peerID]
	if !ok {
		return nil, fmt.Errorf("unknown peer ID %d", peerID)
	}

	// Non-blocking dial: the connection is set up in the background. A blocking dial
	// here held c.mu for a full second per offline node, which serialized every
	// request behind it and delivered requests to live nodes seconds late.
	conn, err := grpc.Dial(peerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to peer %d at %s: %w", peerID, peerAddr, err)
	}

	client := pb.NewPbftNodeClient(conn)
	c.grpcClients[peerID] = client
	c.clientConn[peerID] = conn
	log.Printf("[ClientOrch] Established gRPC connection to Node %d", peerID)
	return client, nil
}

func (c *ClientOrchestrator) CloseConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, conn := range c.clientConn {
		log.Printf("[ClientOrch] Closing connection to Node %d", id)
		conn.Close()
	}
	c.clientConn = make(map[int]*grpc.ClientConn)
	c.grpcClients = make(map[int]pb.PbftNodeClient)
}

func (c *ClientOrchestrator) SubmitTransfer(clientID, sender, receiver string, amount int32) (string, error) {
	c.mu.Lock()
	clientState, ok := c.clientStates[clientID]
	if !ok {
		c.mu.Unlock()
		return "", fmt.Errorf("unknown client ID %s", clientID)
	}
	clientState.Timestamp++
	ts := clientState.Timestamp
	c.mu.Unlock()

	req := &pb.ClientRequest{
		Transaction: &pb.Transaction{
			Sender:   sender,
			Receiver: receiver,
			Amount:   amount,
		},
		Timestamp: ts,
		ClientId:  clientID,
	}

	log.Printf("[%s] Submitting Transfer (ts=%d): (%s, %s, %d)", clientID, ts, sender, receiver, amount)
	return c.submitRequestInternal(req, c.replyQuorum, RequestTimeout, true)
}

func (c *ClientOrchestrator) SubmitBalance(clientID, sender string) (string, error) {
	c.mu.Lock()
	clientState, ok := c.clientStates[clientID]
	if !ok {
		c.mu.Unlock()
		return "", fmt.Errorf("unknown client ID %s", clientID)
	}
	clientState.Timestamp++
	ts := clientState.Timestamp
	c.mu.Unlock()

	readOnlyReq := &pb.ClientRequest{
		Transaction: &pb.Transaction{
			Sender: sender,
		},
		Timestamp: ts,
		ClientId:  clientID,
	}

	log.Printf("[%s] Submitting Balance Check (ts=%d): (%s)", clientID, ts, sender)

	// Read-only fast path: one round, 2f+1 matching replies, no retransmission.
	result, err := c.submitRequestInternal(readOnlyReq, c.readQuorum, ReadOnlyTimeout, false)

	if err != nil && (strings.Contains(err.Error(), "client timeout") || strings.Contains(err.Error(), "no quorum")) {
		log.Printf("[%s] Read-only path for (ts=%d) failed. Falling back to full consensus.", clientID, ts)

		c.mu.Lock()
		clientState.Timestamp++
		fallbackTs := clientState.Timestamp
		c.mu.Unlock()

		// Sent as a zero-amount self-transfer so the replicas order it through
		// consensus instead of answering it on the read-only path again; it executes
		// as a balance read (see isConsensusRead in node.go).
		fallbackReq := &pb.ClientRequest{
			Transaction: &pb.Transaction{
				Sender:   sender,
				Receiver: sender,
				Amount:   0,
			},
			Timestamp: fallbackTs,
			ClientId:  clientID,
		}

		log.Printf("[%s] Submitting Fallback consensus read (ts=%d) for balance check", clientID, fallbackTs)
		return c.submitRequestInternal(fallbackReq, c.replyQuorum, RequestTimeout, true)
	}

	return result, err
}

// submitRequestInternal sends req to every replica and returns once quorumSize
// replicas sent valid, signed, matching results. With retransmit set, the request
// is re-sent to each replica until it answers or the timeout expires, so it
// survives view changes (PBFT clients retransmit until they get f+1 replies).
func (c *ClientOrchestrator) submitRequestInternal(req *pb.ClientRequest, quorumSize int, timeout time.Duration, retransmit bool) (string, error) {
	ts := req.Timestamp
	clientID := req.ClientId

	mainCtx, mainCancel := context.WithTimeout(context.Background(), timeout)
	defer mainCancel()

	replyChan := make(chan *pb.ClientReply, len(c.nodeAddrs))
	replyCounts := make(map[string]int)
	replied := make(map[int32]bool)
	var wg sync.WaitGroup
	wg.Add(len(c.nodeAddrs))

	for peerID := range c.nodeAddrs {
		go func(pID int) {
			defer wg.Done()

			for attempt := 1; ; attempt++ {
				client, err := c.GetGrpcClient(pID)
				if err != nil {
					log.Printf("[%s] DEBUG: Failed to get client for Node %d: %v", clientID, pID, err)
				} else {
					attemptCtx, attemptCancel := context.WithTimeout(mainCtx, AttemptTimeout)
					res, err := client.SubmitRequest(attemptCtx, req)
					attemptCancel()

					switch {
					case err != nil:
						if attempt == 1 {
							log.Printf("[%s] DEBUG: Error from Node %d: %v", clientID, pID, err)
						}
					case res.Signature != nil && res.Timestamp == ts && res.ClientId == clientID:
						select {
						case replyChan <- res:
						case <-mainCtx.Done():
						}
						return
					default:
						log.Printf("[%s] DEBUG: No reply yet from Node %d for (ts=%d): %s. Retransmitting.", clientID, pID, ts, res.Result)
					}
				}

				if !retransmit {
					return
				}
				select {
				case <-mainCtx.Done():
					return
				case <-time.After(RetryBackoff):
				}
			}
		}(peerID)
	}

	go func() {
		wg.Wait()
		close(replyChan)
		log.Printf("[%s] All node RPCs for (ts=%d) have completed or timed out.", clientID, ts)
	}()

	for {
		select {
		case <-mainCtx.Done():
			log.Printf("[%s] Client timeout for (ts=%d). Did not receive quorum.", clientID, ts)
			return "failed: client timeout", fmt.Errorf("client timeout")

		case res, ok := <-replyChan:
			if !ok {
				log.Printf("[%s] Failed to get quorum for (ts=%d). All nodes replied or timed out.", clientID, ts)
				return "failed: no quorum", fmt.Errorf("no quorum")
			}

			if res.Timestamp != ts || res.ClientId != clientID {
				log.Printf("[%s] Ignoring stale reply (ts=%d) from Node %d", clientID, res.Timestamp, res.ReplicaId)
				continue
			}
			if replied[res.ReplicaId] {
				continue // count each replica once
			}

			replyData, err := clientReplyDataForSig(res.View, res.Timestamp, res.ClientId, res.ReplicaId, res.Result)
			if err != nil {
				log.Printf("[%s] Failed to serialize reply from Node %d for verification: %v", clientID, res.ReplicaId, err)
				continue
			}
			if !c.verify(int(res.ReplicaId), replyData, res.Signature) {
				log.Printf("[%s] INVALID SIGNATURE from Node %d! (Byzantine). Ignoring.", clientID, res.ReplicaId)
				continue
			}
			replied[res.ReplicaId] = true

			// Match on the result only: replicas that executed the request after a view
			// change report a different view for the same result.
			resultKey := res.Result
			replyCounts[resultKey]++
			log.Printf("[%s] Got valid reply for (ts=%d) from Node %d (view %d). Result: '%s'. Count for this result: %d", clientID, ts, res.ReplicaId, res.View, resultKey, replyCounts[resultKey])

			if replyCounts[resultKey] == quorumSize {
				log.Printf("[%s] QUORUM MET for (ts=%d). Final result: '%s'", clientID, ts, res.Result)

				c.mu.Lock()
				c.clientStates[clientID].LeaderHint = int(res.View) % len(c.nodeAddrs)
				c.mu.Unlock()

				mainCancel()

				return res.Result, nil
			}
		}
	}
}

func (c *ClientOrchestrator) verify(signerID int, data []byte, signature *pb.Signature) bool {
	if signature == nil {
		log.Printf("[ClientOrch] Verification failed - signature is nil")
		return false
	}
	pubKey, ok := c.publicKeys[signerID]
	if !ok {
		log.Printf("[ClientOrch] Verification failed - no public key for signer %d", signerID)
		return false
	}
	hash := sha256.Sum256(data)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], signature.Value)
	if !valid {
		log.Printf("[ClientOrch] Verification FAILED for message signed by %d", signerID)
	}
	return valid
}

func clientReplyDataForSig(v int32, t int64, cid string, i int32, r string) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Encode(t); err != nil {
		return nil, err
	}
	if err := enc.Encode(cid); err != nil {
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
