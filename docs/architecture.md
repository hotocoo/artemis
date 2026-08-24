# Artemis Architecture

## Module map

```
                    +---------------------+
   scope.json ----->|  ACT.Cli / ACT.Desktop   |  composition roots
                    +----------+----------+
                               |
              +----------------+----------------+
              v                                 v
      +-------------+                   +--------------+
      | ACT.Scope   |<------------------| ACT.Policy   |
      | validator,  |                   | gates, e-stop|
      | CIDR, DNS   |                   +--------------+
      +------+------+                        
             |                               
      +------v-----------------------+        
      | ACT.Core                     |        
      | engine, orchestrator, dedup, |        
      | regression, scheduler        |        
      +------+---------------+-------+        
             |               |                
     checks  v          persistence v            
 +-----------+---------+   +---------------+    
 | ACT.Network probes  |   | ACT.Persistence|   
 | ACT.Tls checks      |   | SQLite, audit  |    
 | ACT.Web checks      |   +-------+-------+    
 | ACT.Api surface     |           |            
 | ACT.SourceAnalysis  |   +-------v-------+    
 | ACT.Dependency      |   | ACT.Reporting  |    
 +---------+-----------+   | SARIF/CSV/HTML |    
           |               +----------------+    
     evidence v                                  
      ACT.Evidence redaction                      
                                                   
 optional advisory-only: ACT.Llm                  
```

## Assessment data flow

1. Operator authors a **scope** (file or UI). Structural validation rejects ambiguity.
2. Scope compiles into matchers; DNS gate pins resolutions; policy compiles category/permission grants.
3. Engine builds a **deterministic plan**: metadata-driven selection of checks x contexts, budget-reserved.
4. Discovery runs first; observed services seed contexts for TLS/Web/API checks.
5. Every network byte flows through the **safe HTTP engine**: rate tokens -> scope verdict -> pinned connect -> bounded read -> decompression-capped decode.
6. Findings are fingerprinted (check+target+resource+class), deduplicated against history, scored deterministically, persisted with redacted evidence.
7. Reports render from persisted rows only. SARIF maps severities honestly; coverage states distinguish tested/not-tested/inaccessible/inconclusive.
8. Audit events append to a SHA-256 hash chain; verification walks the whole ledger.

## Key invariants enforced in code (not convention)

- ISafeHttpEngine is the ONLY outbound HTTP path available to checks (DI exposes nothing else).
NaN
- BudgetAccountant.TryReserveRequests gates scheduling; exhaustion skips work instead of overrunning.
- EmergencyStopLatch cancels the linked token that bounds every task.
- IEvidenceFactory redacts at construction time; raw secrets cannot reach persistence through it.
- Checks declare metadata; invalid metadata fails closed before any execution.