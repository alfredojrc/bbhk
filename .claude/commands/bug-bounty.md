---
name: bug-bounty
description: Launch bug bounty agents for security testing
triggers:
  - "bug bounty"
  - "security scan"
  - "hack"
  - "vulnerability"
---

You are launching the Bug Bounty Agent System. You have access to 8 specialized hacker personality agents designed for vulnerability discovery.

## Available Agents:
1. **scout-recon** - Reconnaissance expert
2. **business-logic-breaker** - Payment/logic flaws  
3. **lateral-thinker** - Creative feature abuse
4. **chaos-monkey** - Advanced fuzzing
5. **code-archaeologist** - Legacy vulnerabilities
6. **anarchist-chaos** - Assumption breaking
7. **code-whisperer** - Static analysis
8. **mastermind-strategist** - Exploit chaining

## Quick Commands:

### Full Bug Bounty Scan
```javascript
// Initialize swarm
mcp__claude-flow__swarm_init({ topology: "mesh", maxAgents: 8 })

// Spawn all agents
const agents = [
  "scout-recon", "business-logic-breaker", "lateral-thinker",
  "chaos-monkey", "code-archaeologist", "anarchist-chaos",
  "code-whisperer", "mastermind-strategist"
]
for (const agent of agents) {
  mcp__claude-flow__agent_spawn({ type: agent, name: agent + "-1" })
}

// Run reconnaissance first
mcp__claude-flow__task_orchestrate({
  task: "Perform complete reconnaissance on the target",
  strategy: "sequential",
  priority: "high"
})

// Then parallel discovery
mcp__claude-flow__task_orchestrate({
  task: "Find all vulnerabilities using all available techniques",
  strategy: "parallel",
  priority: "critical"
})

// Finally chain exploits
mcp__claude-flow__task_orchestrate({
  task: "Chain discovered vulnerabilities for maximum impact",
  strategy: "sequential",
  priority: "high"
})
```

### Quick Payment Analysis
```javascript
mcp__claude-flow__agent_spawn({ type: "business-logic-breaker", name: "payment-hunter" })
mcp__claude-flow__task_orchestrate({
  task: "Find payment bypass and race condition vulnerabilities",
  strategy: "adaptive",
  priority: "critical"
})
```

### Chaos Testing
```javascript
mcp__claude-flow__agent_spawn({ type: "chaos-monkey", name: "fuzzer" })
mcp__claude-flow__task_orchestrate({
  task: "Fuzz all input parameters with bizarre and malformed inputs",
  strategy: "parallel",
  priority: "high"
})
```

When the user invokes this command, ask them:
1. What is the target? (must be authorized)
2. What type of scan? (full/quick/specific)
3. Any specific focus areas? (payments/auth/api/etc)

Then spawn the appropriate agents and orchestrate the tasks.