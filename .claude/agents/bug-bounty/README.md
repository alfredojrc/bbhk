# 🎯 Bug Bounty Hacker Agent System

## Overview

This is a collection of 8 specialized AI agents designed to replicate different hacker mindsets and approaches for bug bounty hunting. Each agent has a unique "personality" that forces it to think in unconventional ways to discover vulnerabilities.

## 🤖 Agent Roster

### 1. **Business Logic Breaker** 🤑
- **Focus**: Business logic flaws, race conditions, payment bypasses
- **Mindset**: "Get services for free, break the rules"
- **Specialties**: TOCTOU vulnerabilities, price manipulation, state confusion

### 2. **Lateral Thinker** 📎 (The MacGyver)
- **Focus**: Creative feature misuse, using things for unintended purposes
- **Mindset**: "Every feature is a potential weapon"
- **Specialties**: File upload abuse, SSRF chains, cross-feature exploitation

### 3. **Chaos Monkey** 🐒
- **Focus**: Fuzzing with bizarre, unexpected inputs
- **Mindset**: "The weirder the input, the better"
- **Specialties**: Polyglot payloads, encoding chaos, boundary testing

### 4. **Code Archaeologist** 📜
- **Focus**: Legacy code, forgotten endpoints, historical vulnerabilities
- **Mindset**: "The past never dies, it just gets commented out"
- **Specialties**: Repository mining, backup file discovery, deprecated endpoints

### 5. **Scout** 🗺️ (Reconnaissance Expert)
- **Focus**: Complete attack surface mapping
- **Mindset**: "Know everything before attacking anything"
- **Specialties**: Subdomain enumeration, technology fingerprinting, OSINT

### 6. **Anarchist** 💥
- **Focus**: Breaking all assumptions and rules
- **Mindset**: "Do what nobody would ever do"
- **Specialties**: Protocol violations, impossible states, temporal chaos

### 7. **Code Whisperer** 💻
- **Focus**: Static code analysis without execution
- **Mindset**: "Code doesn't lie, but it doesn't tell the whole truth"
- **Specialties**: Race conditions, logic flaws, crypto vulnerabilities

### 8. **Mastermind** 🧠 (Strategic Leader)
- **Focus**: Chaining vulnerabilities into critical exploits
- **Mindset**: "The whole is greater than the sum of its parts"
- **Specialties**: Exploit chains, impact maximization, attack orchestration

## 🚀 Usage

### Using MCP Commands Directly

Since the CLI commands have known issues, use MCP commands directly:

#### Initialize the Bug Bounty Swarm
```javascript
// Initialize swarm with mesh topology for collaborative hacking
mcp__claude-flow__swarm_init({
  topology: "mesh",
  maxAgents: 8,
  strategy: "adaptive"
})
```

#### Spawn Individual Agents
```javascript
// Spawn a specific agent
mcp__claude-flow__agent_spawn({
  type: "business-logic-breaker",
  name: "logic-hunter-1",
  capabilities: ["race-condition-detection", "payment-analysis"]
})

// Spawn reconnaissance agent
mcp__claude-flow__agent_spawn({
  type: "scout-recon",
  name: "recon-1",
  capabilities: ["subdomain-enumeration", "fingerprinting"]
})
```

#### Orchestrate Bug Bounty Tasks
```javascript
// Full reconnaissance
mcp__claude-flow__task_orchestrate({
  task: "Perform complete reconnaissance on target.com",
  strategy: "sequential",
  priority: "high"
})

// Parallel vulnerability discovery
mcp__claude-flow__task_orchestrate({
  task: "Find all vulnerabilities in api.target.com",
  strategy: "parallel",
  priority: "critical",
  maxAgents: 6
})
```

### Creating Workflows

```javascript
mcp__claude-flow__workflow_create({
  name: "bug-bounty-full-scan",
  steps: [
    {
      name: "reconnaissance",
      agent: "scout-recon",
      task: "Map complete attack surface"
    },
    {
      name: "vulnerability-discovery",
      parallel: true,
      tasks: [
        { agent: "business-logic-breaker", task: "Analyze payment flows" },
        { agent: "chaos-monkey", task: "Fuzz all input parameters" },
        { agent: "code-archaeologist", task: "Find legacy endpoints" },
        { agent: "lateral-thinker", task: "Identify feature abuse vectors" }
      ]
    },
    {
      name: "exploit-development",
      agent: "mastermind-strategist",
      task: "Chain discoveries into maximum impact exploits"
    }
  ]
})
```

## 📋 Workflow Examples

### Example 1: Quick Security Assessment
```javascript
// Quick security check with 3 agents
mcp__claude-flow__swarm_init({ topology: "hierarchical", maxAgents: 3 })

// Spawn recon, fuzzer, and analyzer
mcp__claude-flow__agent_spawn({ type: "scout-recon", name: "scout" })
mcp__claude-flow__agent_spawn({ type: "chaos-monkey", name: "fuzzer" })
mcp__claude-flow__agent_spawn({ type: "code-whisperer", name: "analyzer" })

// Run assessment
mcp__claude-flow__task_orchestrate({
  task: "Quick security assessment of login.target.com",
  strategy: "parallel",
  priority: "high"
})
```

### Example 2: Business Logic Focus
```javascript
// Focus on business logic vulnerabilities
mcp__claude-flow__agent_spawn({
  type: "business-logic-breaker",
  name: "payment-specialist"
})

mcp__claude-flow__task_orchestrate({
  task: "Find payment bypass vulnerabilities in checkout.target.com",
  strategy: "sequential",
  priority: "critical"
})
```

### Example 3: Historical Vulnerability Hunt
```javascript
// Search for forgotten vulnerabilities
mcp__claude-flow__agent_spawn({
  type: "code-archaeologist",
  name: "historian"
})

mcp__claude-flow__task_orchestrate({
  task: "Find exposed backups, old endpoints, and legacy code in target.com",
  strategy: "adaptive",
  priority: "medium"
})
```

## 🎯 Attack Patterns

### The Recon-First Approach
1. Scout performs complete reconnaissance
2. All agents analyze Scout's findings
3. Parallel exploitation attempts
4. Mastermind chains successful findings

### The Chaos Approach
1. All agents attack simultaneously
2. Anarchist and Chaos Monkey break things
3. Other agents exploit the chaos
4. Mastermind identifies critical chains

### The Surgical Approach
1. Code Whisperer analyzes available code
2. Business Logic Breaker targets specific flows
3. Lateral Thinker finds creative bypasses
4. Focused, high-quality vulnerabilities

## 🛠️ Customization

### Adding New Agents

Create a new file in `/home/kali/bbhk/.claude/agents/bug-bounty/` with:

```yaml
---
name: your-agent-name
description: What this agent does
color: color-name
type: bug-bounty
capabilities:
  - capability-1
  - capability-2
---

Your agent's system prompt here...
```

### Modifying Existing Agents

Edit the markdown files directly. Changes take effect immediately due to hot-reload.

## 📊 Performance Tips

1. **Start with reconnaissance**: Always use Scout first
2. **Use parallel strategies**: Multiple agents can work simultaneously
3. **Chain findings**: Always run Mastermind after discovery phase
4. **Document everything**: Agents output detailed reports
5. **Iterate quickly**: Spawn new agents based on findings

## 🔧 Troubleshooting

### If agents aren't responding:
```javascript
// Check agent status
mcp__claude-flow__agent_list({ swarmId: "default" })

// Check task status
mcp__claude-flow__task_status({ taskId: "your-task-id" })
```

### If CLI commands hang:
- Don't use `npx claude-flow@alpha` commands
- Use MCP commands directly as shown above
- Known issue with CLI (GitHub Issue #655)

## 🎪 The Hacker Mindset

Remember: These agents replicate how real hackers think:

1. **Assumption Breaking**: Every rule has an exception
2. **Creative Misuse**: Features are just vulnerabilities in disguise
3. **Persistence**: If one approach fails, try 100 more
4. **Chaining**: Low + Low = Critical
5. **Documentation**: A good PoC is worth a thousand words

## 📈 Success Metrics

Track your bug bounty success with:
- Number of vulnerabilities found per agent
- Severity distribution
- Time to discovery
- Chain complexity
- Bounty values

## 🔐 Ethical Usage

These agents are designed for:
- ✅ Authorized bug bounty programs
- ✅ Penetration testing with permission
- ✅ Security research on your own systems
- ❌ NOT for unauthorized access
- ❌ NOT for malicious purposes

## 🚀 Getting Started

1. Initialize the swarm
2. Spawn your agents
3. Define your target (with authorization!)
4. Orchestrate the hunt
5. Review findings
6. Chain vulnerabilities
7. Write reports
8. Claim bounties!

Happy hunting! 🎯🐛💰