# pbft-demo

A replicated bank ledger that keeps working when some of its replicas misbehave. Seven replicas run a linear variant of PBFT (Practical Byzantine Fault Tolerance) over gRPC and agree on the order of transfers between ten accounts, even while up to two of them crash, forge signatures, stall, ignore some peers, or send different peers conflicting proposals.

Written for a graduate distributed systems course (Fall 2025), with later fixes to view changes and liveness.

## How it works

With n = 7 replicas the system tolerates f = 2 faulty ones. Any 2f + 1 = 5 replicas form a quorum, and two quorums always share at least one honest replica.

A client sends each request to every replica. The primary for the current view (view mod 7) gives the request the next sequence number and broadcasts a signed PRE-PREPARE. In this linear version the backups never talk to each other. Each backup sends its PREPARE only to the primary, which waits for 2f of them and then broadcasts a FULL-PREPARE that carries all of those signatures as proof. COMMIT and FULL-COMMIT repeat the pattern. Every replica executes requests strictly in sequence order and sends the client a signed reply, and the client takes a result once f + 1 replicas agree on it. Normal-case traffic grows linearly with the number of replicas instead of quadratically, at the cost of an extra hop through the primary.

Balance checks skip consensus. Each replica answers from its own copy and the client needs 2f + 1 matching answers. When it doesn't get them, for instance because some replicas are partway through a transfer, it resends the read as a zero-amount transfer to itself, which goes through the normal ordering path and comes back as a balance.

Every protocol message and reply is signed with ECDSA P-256. The `key0.priv` to `key6.pub` files are throwaway test keys, and `go run ./cmd/keygen` generates a new set.

### View changes

A backup starts a 5 second timer when it accepts a PRE-PREPARE. If the request still hasn't executed when the timer fires, the backup gives up on the primary and broadcasts a VIEW-CHANGE listing every request it has prepared, each with its prepare certificate. A replica that sees f + 1 VIEW-CHANGEs for a higher view joins in, since at least one of them came from an honest replica. Once the next primary holds 2f + 1, it sends a NEW-VIEW that re-proposes each prepared request at its original sequence number, fills any gaps with no-ops, and then proposes the client requests that were still waiting. If the new primary is faulty as well, a second timer (10 seconds, doubling each time) moves everyone on to the view after it.

Clients keep resending a request until they have f + 1 matching replies, so a view change only shows up to them as a slower answer.

## Fault injection

Each replica takes an `--attack` flag, which the harness fills in from the test file.

| Attack | What the replica does |
|---|---|
| `crash` | Never sends PREPARE, COMMIT, FULL-PREPARE, FULL-COMMIT or NEW-VIEW, and never answers clients. As primary it still sends PRE-PREPAREs, so the backups see it stall. |
| `sign` | Corrupts every signature it produces. |
| `dark(n6,n7)` | Silently drops every message it would send to the listed replicas. |
| `time` | As primary, holds each request for 500 ms before proposing it. |
| `equivocation(n6,n7)` | As primary, gives each request two sequence numbers and sends the second one only to the listed replicas. |

## Running it

You need Go 1.25 or newer.

```
go build -o node_app.exe ./cmd/node
go run .
```

The harness launches replicas from `node_app.exe` in the current directory on every OS, so build it under that name even on Linux or macOS.

It reads `CSE535-F25-Project-2-Testcases.csv`, asks which set to run (or `all`), starts the live replicas on 127.0.0.1:50051–50057 with their attack flags, waits 10 seconds for them to boot and then submits the set's transactions concurrently. When the set is done you can look inside any replica. Replica IDs in these commands start at 0, so 0 is n1.

```
printdb <id>              balances
printlog <id>             log entries with view, status and content
printstatus <id> <seq>    status of one sequence number
printview <id>            VIEW-CHANGE messages the replica has seen
run <set>, rerun, next, exit
```

## Test sets

Each CSV row holds a set number, one operation, and (on the set's first row) the live replicas, the Byzantine replicas and their attacks:

```
5,"(A, J, 1)","[n1, n2, n3, n4, n5, n6, n7]",[n1],"[equivocation(n6, n7)]"
```

`(A, J, 1)` moves 1 from A to J and `(E)` reads E's balance. Every account starts at 10 and every set starts from a clean state.

| Set | Live | Faults | What happens |
|---|---|---|---|
| 1 | all 7 | none | normal case |
| 2 | n1–n5 | none | exactly 2f + 1 replicas, so every vote counts |
| 3 | n1–n6 | n2 crash | commits without n2 |
| 4 | n1–n6 | n1 time, dark(n6) | slower, and n6 falls behind because it never hears from the primary |
| 5 | all 7 | n1 equivocation(n6, n7) | the duplicate sequence numbers stall execution, n2 takes over and everything commits |
| 6 | all 7 | n1 time, dark(n6), equivocation(n7) | same view change, and n6 catches up from the NEW-VIEW |
| 7 | n1–n5 | n3 sign | nothing commits: two replicas down plus a forger is three faults, one more than f |
| 8 | n1–n6 | n1 equivocation(n5, n6) | nothing prepares in view 0, so n2 takes over and commits the requests |
| 9 | all 7 | n1, n2 crash | n2 never sends its NEW-VIEW, so a second view change hands view 2 to n3 |
| 10 | all 7 | n7 dark(n1, n2) | 50 transfers go through while a backup drops messages to two peers |

## Code layout

```
cmd/node      replica entry point, one process per replica
cmd/keygen    generates the ECDSA key files
node/         the protocol: normal case, view change, execution and the fault behaviors
client/       client that broadcasts requests and counts signed replies
crypto/       key loading
proto/        gRPC service and message definitions
main.go       test harness
```

## Limitations

There is no checkpointing, so the log is never truncated and the watermark window simply slides forward as requests execute. There is no state transfer either. A replica that was kept in the dark only catches up when a NEW-VIEW re-proposes the log, as in set 6. VIEW-CHANGE and NEW-VIEW signatures cover a summary of the message rather than every field, though the new primary re-verifies each prepare certificate it relies on and the backups check the signature on every re-proposal. Membership is fixed at seven replicas on localhost.
