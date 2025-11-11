package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"

	"bft-DarkBrewww/crypto"
	"bft-DarkBrewww/node"
	pb "bft-DarkBrewww/proto"
)

const (
	NumNodes     = 7
	F            = 2
	NodeBasePort = 50051
)

func main() {
	nodeID := flag.Int("id", -1, "Node ID (0 to N-1)")
	attackType := flag.String("attack", "none", "Type of Byzantine attack to simulate")
	flag.Parse()

	if *nodeID == -1 {
		log.Fatalf("Node ID is required. Use --id flag.")
	}

	nodeAddresses := make(map[int]string)
	for i := 0; i < NumNodes; i++ {
		nodeAddresses[i] = fmt.Sprintf("127.0.0.1:%d", NodeBasePort+i)
	}

	myPrivKey, err := crypto.LoadPrivateKey(*nodeID)
	if err != nil {
		log.Fatalf("Node %d failed to load private key: %v", *nodeID, err)
	}
	pubKeys, err := crypto.LoadAllPublicKeys(NumNodes)
	if err != nil {
		log.Fatalf("Node %d failed to load public keys: %v", *nodeID, err)
	}
	log.Printf("Node %d keys loaded successfully.", *nodeID)

	n, err := node.NewNode(*nodeID, nodeAddresses, F, myPrivKey, pubKeys, *attackType)
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}

	lis, err := net.Listen("tcp", nodeAddresses[*nodeID])
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", nodeAddresses[*nodeID], err)
	}

	s := grpc.NewServer()
	pb.RegisterPbftNodeServer(s, n)

	log.Printf("Node %d (Attack: %s) listening on %s", *nodeID, *attackType, nodeAddresses[*nodeID])
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
