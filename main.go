package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"bft-DarkBrewww/client"
	"bft-DarkBrewww/crypto"
	pb "bft-DarkBrewww/proto"
)

// --- System Configuration ---
const (
	NumNodes     = 7
	F            = 2
	NodeBasePort = 50051
	TestCasesCSV = "CSE535-F25-Project-2-Testcases.csv"
)

var nodeAddresses = make(map[int]string)

// allTestSets holds parsed test sets for runtime access from helper commands
var allTestSets []TestSet

func init() {
	for i := 0; i < NumNodes; i++ {
		// Force IPv4
		nodeAddresses[i] = fmt.Sprintf("127.0.0.1:%d", NodeBasePort+i)
	}
}

// Struct to hold a parsed test set from the 5-column CSV
type TestSet struct {
	SetNumber    int
	Transactions []interface{} // Can hold Transaction or BalanceCheck
	LiveNodes    []int
	Byzantine    map[int][]string // map[nodeID] -> attackType
	Attacks      []string         // Raw attack strings
}

// Transaction struct for (s, r, amt)
type Transaction struct {
	Sender   string
	Receiver string
	Amount   int32
}

// BalanceCheck struct for (s)
type BalanceCheck struct {
	Sender string
}

// --- Node Process Management ---
var nodeProcesses = make(map[int]*exec.Cmd)

// startNode launches a node as a child process
func startNode(id int, attackTypes []string) error {
	if _, ok := nodeProcesses[id]; ok {
		log.Printf("[Harness] Node %d is already running.", id)
		return nil
	}

	// Use the .exe extension for Windows
	exeName := "node_app.exe"
	exePath, err := filepath.Abs(exeName)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for %s: %w", exeName, err)
	}

	attackString := "none"
	if len(attackTypes) > 0 {
		attackString = strings.Join(attackTypes, ";")
	}

	cmd := exec.Command(exePath,
		"--id", strconv.Itoa(id),
		"--attack", attackString,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start node %d (%s): %w", id, exePath, err)
	}

	nodeProcesses[id] = cmd
	log.Printf("[Harness] Started Node %d (PID: %d) with attack: '%s'", id, cmd.Process.Pid, attackString)
	return nil
}

// stopAllNodes kills all running child node processes
func stopAllNodes() {
	log.Println("[Harness] Stopping all node processes...")
	for id, cmd := range nodeProcesses {
		if cmd.Process != nil {
			if err := cmd.Process.Kill(); err != nil {
				log.Printf("[Harness] Failed to kill node %d (PID: %d): %v", id, cmd.Process.Pid, err)
			} else {
				log.Printf("[Harness] Killed Node %d (PID: %d)", id, cmd.Process.Pid)
			}
		}
		cmd.Wait()
	}
	nodeProcesses = make(map[int]*exec.Cmd)
}

func main() {
	log.Println("Starting PBFT Test Harness and Client Orchestrator...")

	defer stopAllNodes()

	// --- Load Cryptographic Keys ---
	log.Println("[Harness] Loading all public keys...")
	pubKeys, err := crypto.LoadAllPublicKeys(NumNodes)
	if err != nil {
		log.Fatalf("Failed to load public keys: %v", err)
	}
	log.Println("[Harness] Public keys loaded.")

	// --- Initialize Client Orchestrator ---
	orchestrator := client.NewClientOrchestrator(nodeAddresses, F, pubKeys)
	defer orchestrator.CloseConnections()

	// --- Parse Test Cases ---
	testSets, err := parseTestCases(TestCasesCSV)
	if err != nil {
		log.Fatalf("Failed to parse test cases from %s: %v", TestCasesCSV, err)
	}

	// --- Display Available Test Cases ---
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("\n--- Available Test Cases ---")
	// make test sets globally available to interactive commands
	allTestSets = testSets
	for _, ts := range allTestSets {
		fmt.Printf("Test Set %d: Live Nodes: %v, Byzantine Nodes: %v\n", ts.SetNumber, ts.LiveNodes, ts.Attacks)
	}

	// --- Prompt User to Select Test Case ---
	var selectedSet *TestSet
	for {
		fmt.Print("\nEnter the test set number to run (or 'all' to run all): ")
		if !scanner.Scan() {
			log.Println("Scanner error, exiting.")
			return
		}
		input := strings.TrimSpace(scanner.Text())

		if input == "all" {
			// Run all test sets
			for _, ts := range testSets {
				executeTestSet(ts, orchestrator, scanner)
			}
			log.Println("--- All test sets completed. ---")
			return
		}

		setNum, err := strconv.Atoi(input)
		if err != nil {
			fmt.Printf("Invalid input. Please enter a valid test set number or 'all'.\n")
			continue
		}

		// Find the selected test set
		found := false
		for i := range testSets {
			if testSets[i].SetNumber == setNum {
				selectedSet = &testSets[i]
				found = true
				break
			}
		}

		if !found {
			fmt.Printf("Test set %d not found. Please enter a valid test set number.\n", setNum)
			continue
		}

		break
	}

	// --- Execute the Selected Test Set ---
	if selectedSet != nil {
		executeTestSet(*selectedSet, orchestrator, scanner)
		log.Println("--- Test set completed. ---")
	}
}

// executeTestSet runs a single test set
func executeTestSet(ts TestSet, orchestrator *client.ClientOrchestrator, scanner *bufio.Scanner) {
	// The executeTestSet function now supports repeating or running other sets
	// from the interactive prompt. It will loop until the user issues 'next'
	// to return to the main selector or 'exit' to quit the program.
	current := ts
restart:
	for {
		fmt.Printf("\n--- Press Enter to start Test Set %d ---", current.SetNumber)
		fmt.Printf("\n(Live: %v, Byzantine: %v)\n", current.LiveNodes, current.Byzantine)
		scanner.Scan()

		log.Printf("Executing Test Set %d with live nodes: %v", current.SetNumber, current.LiveNodes)

		// --- 1. Start all "Live" nodes ---
		for _, nodeID := range current.LiveNodes {
			// Note: CSV is 1-based, internal is 0-based
			internalID := nodeID - 1
			attackList := current.Byzantine[internalID]

			if err := startNode(internalID, attackList); err != nil {
				log.Fatalf("[Harness] CRITICAL: Failed to start node %d: %v", internalID, err)
			}
		}

		log.Println("[Harness] All nodes for this set are starting. Waiting 10 seconds for them to boot...")
		time.Sleep(10 * time.Second)

		// --- 2. Submit all operations for this set ---
		fmt.Println("\n--- Submitting operations for this set ---")
		var wg sync.WaitGroup

		for i, op := range current.Transactions {
			wg.Add(1)

			if tx, ok := op.(Transaction); ok {
				// Read-Write Transfer
				clientID := fmt.Sprintf("client-%d", i%10)
				go func(cid, sender, receiver string, amt int32) {
					defer wg.Done()
					log.Printf("[Client %s] Submitting Transfer: (%s, %s, %d)", cid, sender, receiver, amt)
					result, err := orchestrator.SubmitTransfer(cid, sender, receiver, amt)
					if err != nil {
						log.Printf("[Client %s] Transfer FAILED: %v", cid, err)
					} else {
						log.Printf("[Client %s] Transfer COMPLETE. Result: %s", cid, result)
					}
				}(clientID, tx.Sender, tx.Receiver, tx.Amount)

			} else if bc, ok := op.(BalanceCheck); ok {
				// Read-Only Balance
				clientID := fmt.Sprintf("client-%d", i%10)
				go func(cid, sender string) {
					defer wg.Done()
					log.Printf("[Client %s] Submitting Balance Check: (%s)", cid, sender)
					result, err := orchestrator.SubmitBalance(cid, sender)
					if err != nil {
						log.Printf("[Client %s] Balance Check FAILED: %v", cid, err)
					} else {
						log.Printf("[Client %s] Balance Check COMPLETE. Result: %s", cid, result)
					}
				}(clientID, bc.Sender)
			}
		}

		log.Println("--- Waiting for all transactions in this set to complete ---")
		wg.Wait()
		log.Println("--- All transactions for this set are complete ---")

		// Flush failed/old connections *before* the prompt
		log.Println("[Harness] Flushing all client connections...")
		orchestrator.CloseConnections()

		// --- 3. Interactive Command Prompt ---
		fmt.Println("\n--- Test Set Complete ---")
		for {
			fmt.Print("Enter command (printdb <id>, printlog <id>, printstatus <id> <seq>, printview <id>, run <set>, rerun, next, exit): ")
			if !scanner.Scan() {
				log.Println("Scanner error, exiting.")
				stopAllNodes()
				return
			}
			cmdLine := scanner.Text()
			parts := strings.Fields(cmdLine)
			if len(parts) == 0 {
				continue
			}

			command := parts[0]
			// Support running another test set or re-running the current one
			if command == "run" {
				if len(parts) < 2 {
					log.Println("Usage: run <setNumber>")
					continue
				}
				setNum, err := strconv.Atoi(parts[1])
				if err != nil {
					log.Printf("Invalid set number '%s'", parts[1])
					continue
				}
				// Find requested set
				found := false
				for _, s := range allTestSets {
					if s.SetNumber == setNum {
						// Stop current nodes and switch to requested
						stopAllNodes()
						orchestrator.CloseConnections()
						current = s
						// restart the outer loop to run the new set
						goto restart
					}
				}
				if !found {
					log.Printf("Test set %d not found.", setNum)
				}
				continue
			}
			if command == "rerun" {
				stopAllNodes()
				orchestrator.CloseConnections()
				// restart same set
				goto restart
			}

			if command == "next" {
				// --- 4. FLUSH System State ---
				stopAllNodes()
				log.Println("[Harness] System state FLUSHED. Proceeding to next set.")
				orchestrator.CloseConnections()
				return
			}
			if command == "exit" {
				log.Println("Exiting test harness.")
				stopAllNodes()
				os.Exit(0)
			}

			// Remaining commands operate on nodes in the current set
			if len(parts) < 2 {
				log.Println("Invalid command. Missing node ID.")
				continue
			}

			nodeID, err := strconv.Atoi(parts[1])
			if err != nil || nodeID < 0 || nodeID >= NumNodes {
				log.Printf("Invalid node ID '%s'. Must be 0-%d.", parts[1], NumNodes-1)
				continue
			}

			if _, ok := nodeProcesses[nodeID]; !ok {
				log.Printf("Node %d is not live in this test set. Command ignored.", nodeID)
				continue
			}

			queryClient, err := orchestrator.GetGrpcClient(nodeID) // This is now exported
			if err != nil {
				log.Printf("Error connecting to node %d: %v", nodeID, err)
				continue
			}
			ctxQuery, cancelQuery := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancelQuery()

			switch command {
			case "printdb":
				res, err := queryClient.GetNodeState(ctxQuery, &pb.StateRequest{})
				if err != nil {
					log.Printf("Error from GetNodeState on node %d: %v", nodeID, err)
				} else {
					fmt.Printf("--- DB of Node %d (View: %d, LastExec: %d) ---\n", res.NodeId, res.CurrentView, res.LastExecutedSequence)
					keys := make([]string, 0, len(res.Db))
					for k := range res.Db {
						keys = append(keys, k)

					}
					sort.Strings(keys)
					for _, k := range keys {
						fmt.Printf("%s: %d\n", k, res.Db[k])
					}
				}

			case "printlog":
				res, err := queryClient.GetNodeState(ctxQuery, &pb.StateRequest{})
				if err != nil {
					log.Printf("Error from GetNodeState on node %d: %v", nodeID, err)
				} else {
					fmt.Printf("--- Log of Node %d (View: %d, LastExec: %d) ---\n", res.NodeId, res.CurrentView, res.LastExecutedSequence)
					for _, entry := range res.Log {
						fmt.Printf("Seq: %d, View: %d, Status: %s, Content: %s\n", entry.SequenceNumber, entry.View, entry.Status, entry.Content)
					}
				}

			case "printstatus":
				if len(parts) < 3 {
					log.Println("Usage: printstatus <id> <seq>")
					continue
				}
				seq, err := strconv.ParseInt(parts[2], 10, 64)
				if err != nil {
					log.Printf("Invalid sequence number '%s'", parts[2])
					continue
				}
				res, err := queryClient.GetNodeState(ctxQuery, &pb.StateRequest{SequenceNumber: seq})
				if err != nil {
					log.Printf("Error from GetNodeState on node %d: %v", nodeID, err)
				} else {
					fmt.Printf("Status of Seq %d at Node %d: %s\n", seq, res.NodeId, res.StatusForSeq)
				}

			case "printview":
				res, err := queryClient.GetNodeState(ctxQuery, &pb.StateRequest{})
				if err != nil {
					log.Printf("Error from GetNodeState on node %d: %v", nodeID, err)
				} else {
					fmt.Printf("--- View Change History of Node %d (Current View: %d) ---\n", res.NodeId, res.CurrentView)
					if len(res.ViewChangeHistory) == 0 {
						fmt.Println("No view change messages recorded.")
					} else {
						// Sort by view number first, then by sender ID
						sort.Slice(res.ViewChangeHistory, func(i, j int) bool {
							if res.ViewChangeHistory[i].NewView != res.ViewChangeHistory[j].NewView {
								return res.ViewChangeHistory[i].NewView < res.ViewChangeHistory[j].NewView
							}
							return res.ViewChangeHistory[i].ReplicaId < res.ViewChangeHistory[j].ReplicaId
						})

						for i, vcMsg := range res.ViewChangeHistory {
							fmt.Printf("  [%d] From Replica: %d, Target View: %d, P-Set Size: %d\n", i+1, vcMsg.ReplicaId, vcMsg.NewView, len(vcMsg.PreparedProof))
						}
					}
				}

			default:
				log.Printf("Unknown command '%s'", command)
			}
		}
	}
}

// parseTestCases reads the 5-column CSV file for Project 2
func parseTestCases(filepath string) ([]TestSet, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("could not open file %s: %w", filepath, err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true

	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("could not read csv data: %w", err)
	}

	if len(records) < 1 {
		return nil, fmt.Errorf("empty test case file")
	}

	// Skip header
	records = records[1:]

	var testSets []TestSet
	var currentSet *TestSet = nil

	// Regex for parsing:
	txRegex := regexp.MustCompile(`\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*(\d+)\s*\)`) // (Sender, Receiver, Amount)
	bcRegex := regexp.MustCompile(`\(\s*([^,]+)\s*\)`)                           // (Sender)
	nodeRegex := regexp.MustCompile(`n(\d+)`)                                    // n1, n2, etc.

	for i, row := range records {
		if len(row) < 5 {
			continue // Skip empty/malformed rows
		}

		// 1. Check for new set number
		if row[0] != "" {
			setNum, err := strconv.Atoi(row[0])
			if err != nil {
				return nil, fmt.Errorf("invalid set number on row %d: %s", i+2, row[0])
			}

			if currentSet != nil {
				testSets = append(testSets, *currentSet)
			}

			currentSet = &TestSet{
				SetNumber:    setNum,
				Transactions: make([]interface{}, 0),
				LiveNodes:    make([]int, 0),
				Byzantine:    make(map[int][]string),
				Attacks:      make([]string, 0),
			}

			// 2. Parse Live Nodes
			matches := nodeRegex.FindAllStringSubmatch(row[2], -1)
			for _, match := range matches {
				id, _ := strconv.Atoi(match[1])
				currentSet.LiveNodes = append(currentSet.LiveNodes, id) // 1-based ID
			}
			sort.Ints(currentSet.LiveNodes)

			// 3. Parse Byzantine Nodes
			byzantineNodes := make([]int, 0)
			matches = nodeRegex.FindAllStringSubmatch(row[3], -1)
			for _, match := range matches {
				id, _ := strconv.Atoi(match[1])
				byzantineNodes = append(byzantineNodes, id-1) // 1-based ID
			}

			// 4. Parse Attacks and map to Byzantine nodes (NEW LOGIC)
			attackStr := strings.Trim(row[4], "[]")
			if attackStr != "" {
				attacks := strings.Split(attackStr, ";")
				currentSet.Attacks = attacks

				// Find the primary for this view (assume view 0, so node 0)
				primaryID := 0 // n1 is 0-based ID 0

				for _, attack := range attacks {
					attack = strings.TrimSpace(attack)
					if attack == "" {
						continue
					}

					// Leader-specific attacks
					if attack == "time" || strings.HasPrefix(attack, "equivocation") {
						// Assign this attack to the primary (Node 0)
						// This assumes n1 is always the primary in attack specs
						currentSet.Byzantine[primaryID] = append(currentSet.Byzantine[primaryID], attack)
					} else {
						// General attacks (crash, sign, dark) apply to ALL listed byzantine nodes
						for _, byzNodeID := range byzantineNodes {
							currentSet.Byzantine[byzNodeID] = append(currentSet.Byzantine[byzNodeID], attack)
						}
					}
				}
			}
		}

		if currentSet == nil {
			return nil, fmt.Errorf("transaction found before any set number on row %d", i+2)
		}

		// 5. Parse transaction/operation
		opStr := strings.Trim(row[1], `" `)
		if opStr == "" {
			continue
		}

		if matches := txRegex.FindStringSubmatch(opStr); len(matches) == 4 {
			// It's a Read-Write Transfer
			amount, _ := strconv.Atoi(matches[3])
			tx := Transaction{
				Sender:   strings.TrimSpace(matches[1]),
				Receiver: strings.TrimSpace(matches[2]),
				Amount:   int32(amount),
			}
			currentSet.Transactions = append(currentSet.Transactions, tx)
		} else if matches := bcRegex.FindStringSubmatch(opStr); len(matches) == 2 {
			// It's a Read-Only Balance Check
			bc := BalanceCheck{
				Sender: strings.TrimSpace(matches[1]),
			}
			currentSet.Transactions = append(currentSet.Transactions, bc)
		} else {
			// This warning will no longer fire for valid transactions
			log.Printf("Warning: malformed transaction on row %d: %s", i+2, opStr)
		}
	}

	if currentSet != nil {
		testSets = append(testSets, *currentSet)
	}

	return testSets, nil
}
