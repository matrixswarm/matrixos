package main

import (
    "fmt"
    "log"
    "matrixswarm/core/go_core/bootagent"
)

func main() {
    v, err := bootagent.LoadVault()
    if err != nil {
        log.Fatalf("Vault load error: %v", err)
    }
    if err := bootagent.InitPaths(v); err != nil {
        log.Fatalf("Init paths error: %v", err)
    }
    bootagent.DebugPrint(v)

    fmt.Println("[GO-BOOT_AGENT] swarm_notifier_go is alive.")
    // start worker goroutines here…
}
