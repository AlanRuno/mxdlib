# Security Best Practices for Smart Contract Development

## Introduction

This guide provides security best practices for developing smart contracts on MXD Network. Following these guidelines will help you avoid common vulnerabilities and create more secure, reliable contracts.

**Target Audience**: Smart contract developers using Rust/AssemblyScript/C to compile to WASM

## Table of Contents

1. [General Principles](#general-principles)
2. [Common Vulnerabilities](#common-vulnerabilities)
3. [Safe Coding Patterns](#safe-coding-patterns)
4. [Testing Guidelines](#testing-guidelines)
5. [Deployment Checklist](#deployment-checklist)

## General Principles

### 1. Assume Hostile Input

**Always validate all inputs**, even from trusted sources:

```rust
// BAD: No validation
fn transfer(to: Address, amount: u64) {
    let balance = get_balance(sender());
    set_balance(sender(), balance - amount);  // Can underflow!
    set_balance(to, get_balance(to) + amount);  // Can overflow!
}

// GOOD: Validate everything
fn transfer(to: Address, amount: u64) -> Result<(), Error> {
    if amount == 0 {
        return Err(Error::ZeroAmount);
    }

    let sender_balance = get_balance(sender());
    if sender_balance < amount {
        return Err(Error::InsufficientBalance);
    }

    // Use checked arithmetic
    let new_sender_balance = sender_balance.checked_sub(amount)
        .ok_or(Error::Underflow)?;
    let new_to_balance = get_balance(to).checked_add(amount)
        .ok_or(Error::Overflow)?;

    set_balance(sender(), new_sender_balance);
    set_balance(to, new_to_balance);

    Ok(())
}
```

### 2. Fail Securely

**Always fail safely** - if an error occurs, the contract should revert to a safe state:

```rust
// BAD: Partial state update on error
fn multi_transfer(recipients: Vec<(Address, u64)>) {
    for (to, amount) in recipients {
        transfer(to, amount);  // If this fails halfway, state is corrupted
    }
}

// GOOD: All-or-nothing
fn multi_transfer(recipients: Vec<(Address, u64)>) -> Result<(), Error> {
    // Validate all transfers first
    for (to, amount) in &recipients {
        let balance = get_balance(sender());
        if balance < *amount {
            return Err(Error::InsufficientBalance);  // No state changed yet
        }
    }

    // Execute all transfers
    for (to, amount) in recipients {
        transfer(to, amount)?;  // Revert if any fails
    }

    Ok(())
}
```

### 3. Minimize Attack Surface

**Expose only necessary functions**:

```rust
// BAD: Everything public
pub fn internal_set_balance(addr: Address, amount: u64) {
    set_storage(&addr, &amount);
}

pub fn withdraw(amount: u64) {
    internal_set_balance(sender(), 0);  // Attacker can call internal_set_balance directly!
}

// GOOD: Internal functions private
fn internal_set_balance(addr: Address, amount: u64) {
    set_storage(&addr, &amount);
}

pub fn withdraw(amount: u64) -> Result<(), Error> {
    let balance = get_balance(sender());
    if balance < amount {
        return Err(Error::InsufficientBalance);
    }
    internal_set_balance(sender(), balance - amount);
    Ok(())
}
```

## Common Vulnerabilities

### 1. Reentrancy

**Problem**: Contract calls another contract that calls back into the first contract before the first call completes.

**MXD Protection**: Reentrancy is automatically prevented by the runtime lock.

**Still Be Careful**:
```rust
// VULNERABLE: State updated after external call
fn withdraw(amount: u64) {
    require(balance[sender()] >= amount);
    external_transfer(sender(), amount);  // External call
    balance[sender()] -= amount;  // Too late! Reentrancy could happen
}

// SAFE: State updated before external call
fn withdraw(amount: u64) {
    require(balance[sender()] >= amount);
    balance[sender()] -= amount;  // Update state first
    external_transfer(sender(), amount);  // Then external call
}
```

### 2. Integer Overflow/Underflow

**Problem**: Arithmetic operations exceed type bounds.

**Solution**: Always use checked arithmetic:

```rust
// VULNERABLE
fn add_balance(addr: Address, amount: u64) {
    let balance = get_balance(addr);
    set_balance(addr, balance + amount);  // Can overflow!
}

// SAFE
fn add_balance(addr: Address, amount: u64) -> Result<(), Error> {
    let balance = get_balance(addr);
    let new_balance = balance.checked_add(amount)
        .ok_or(Error::Overflow)?;
    set_balance(addr, new_balance);
    Ok(())
}
```

### 3. Unchecked Return Values

**Problem**: Not checking if operations succeeded.

```rust
// VULNERABLE
fn process() {
    let result = risky_operation();
    // What if it failed?
    use_result(result);
}

// SAFE
fn process() -> Result<(), Error> {
    let result = risky_operation()?;  // Propagate error
    use_result(result);
    Ok(())
}
```

### 4. Front-Running

**Problem**: Attacker sees your transaction and submits their own with higher gas to execute first.

**Mitigation**: Use commit-reveal schemes:

```rust
// Phase 1: Commit
fn commit_bid(hash: Hash) {
    commitments[sender()] = hash;
}

// Phase 2: Reveal (after commit period)
fn reveal_bid(amount: u64, nonce: u64) {
    let expected_hash = sha256(&[amount, nonce]);
    require(commitments[sender()] == expected_hash);
    process_bid(amount);
}
```

### 5. Timestamp Dependence

**Problem**: Relying on block timestamp which validators can manipulate slightly.

```rust
// VULNERABLE
fn lottery() {
    let winner = block_timestamp() % participants.len();
    pay_winner(winner);
}

// BETTER: Use block hash
fn lottery() {
    let random = block_hash() % participants.len();
    pay_winner(random);
}

// BEST: Use VRF or commit-reveal
```

### 6. Denial of Service (DoS)

**Problem**: Attacker makes contract unusable.

**Gas Limit DoS**:
```rust
// VULNERABLE: Unbounded loop
fn pay_everyone() {
    for recipient in recipients {  // What if there are 1 million?
        transfer(recipient, amount);  // Runs out of gas
    }
}

// SAFE: Batch processing
fn pay_batch(start: u32, end: u32) -> Result<(), Error> {
    require(end - start <= 100);  // Max 100 per batch
    for i in start..end {
        transfer(recipients[i], amount)?;
    }
    Ok(())
}
```

**Storage DoS**:
```rust
// VULNERABLE: Unlimited storage growth
fn add_entry(data: Vec<u8>) {
    entries.push(data);  // Attacker can fill storage
}

// SAFE: Limit storage
fn add_entry(data: Vec<u8>) -> Result<(), Error> {
    require(entries.len() < MAX_ENTRIES);
    require(data.len() <= MAX_DATA_SIZE);
    entries.push(data);
    Ok(())
}
```

## Safe Coding Patterns

### 1. Checks-Effects-Interactions

**Always follow this order**:

```rust
fn withdraw(amount: u64) -> Result<(), Error> {
    // 1. CHECKS
    require(balance[sender()] >= amount)?;
    require(amount > 0)?;

    // 2. EFFECTS (update state)
    balance[sender()] -= amount;

    // 3. INTERACTIONS (external calls)
    external_transfer(sender(), amount)?;

    Ok(())
}
```

### 2. Pull Over Push

**Don't push payments, let users pull**:

```rust
// BAD: Push payments
fn distribute_rewards() {
    for user in users {
        transfer(user, reward);  // Fails if one transfer fails
    }
}

// GOOD: Pull payments
fn claim_reward() -> Result<(), Error> {
    let amount = pending_rewards[sender()];
    require(amount > 0)?;

    pending_rewards[sender()] = 0;  // Update first
    transfer(sender(), amount)?;

    Ok(())
}
```

### 3. Rate Limiting

**Prevent abuse with rate limits**:

```rust
struct RateLimit {
    last_action: u64,
    action_count: u32,
}

fn rate_limited_action() -> Result<(), Error> {
    let limit = rate_limits[sender()];
    let now = block_timestamp();

    // Reset counter every 24 hours
    if now - limit.last_action > 86400 {
        limit.action_count = 0;
    }

    require(limit.action_count < MAX_ACTIONS_PER_DAY)?;

    limit.action_count += 1;
    limit.last_action = now;

    perform_action();
    Ok(())
}
```

### 4. Circuit Breakers

**Add emergency stop mechanism**:

```rust
struct Contract {
    paused: bool,
    owner: Address,
}

fn pause() -> Result<(), Error> {
    require(sender() == self.owner)?;
    self.paused = true;
    Ok(())
}

fn withdraw(amount: u64) -> Result<(), Error> {
    require(!self.paused)?;  // Check if paused
    // ... rest of function
}
```

### 5. Access Control

**Implement proper permissions**:

```rust
mod roles {
    pub const OWNER: u8 = 1;
    pub const ADMIN: u8 = 2;
    pub const USER: u8 = 3;
}

fn only_owner() -> Result<(), Error> {
    require(roles[sender()] == roles::OWNER)?;
    Ok(())
}

fn admin_function() -> Result<(), Error> {
    only_owner()?;
    // ... admin logic
}
```

## Testing Guidelines

### 1. Unit Tests

**Test every function thoroughly**:

```rust
#[test]
fn test_transfer_success() {
    set_balance(alice(), 100);
    transfer(bob(), 50).unwrap();
    assert_eq!(get_balance(alice()), 50);
    assert_eq!(get_balance(bob()), 50);
}

#[test]
fn test_transfer_insufficient_balance() {
    set_balance(alice(), 100);
    let result = transfer(bob(), 150);
    assert!(result.is_err());
    assert_eq!(get_balance(alice()), 100);  // Unchanged
}

#[test]
fn test_transfer_overflow() {
    set_balance(alice(), 100);
    set_balance(bob(), u64::MAX - 50);
    let result = transfer(bob(), 100);
    assert!(result.is_err());  // Should prevent overflow
}
```

### 2. Integration Tests

**Test contract interactions**:

```rust
#[test]
fn test_multi_contract_interaction() {
    let token = deploy_token_contract();
    let exchange = deploy_exchange_contract();

    token.transfer(exchange.address(), 1000);
    exchange.swap(token.address(), 100);

    assert_eq!(token.balance_of(user()), 100);
}
```

### 3. Fuzz Testing

**Use property-based testing**:

```rust
#[quickcheck]
fn prop_transfer_preserves_total(amount: u64) -> bool {
    let initial_total = get_balance(alice()) + get_balance(bob());

    if transfer(bob(), amount).is_ok() {
        let final_total = get_balance(alice()) + get_balance(bob());
        initial_total == final_total
    } else {
        true  // Failed transfers don't change state
    }
}
```

### 4. Gas Testing

**Ensure operations fit in gas limits**:

```rust
#[test]
fn test_batch_transfer_gas() {
    let recipients = vec![(addr1(), 100), (addr2(), 100)];
    let gas_before = remaining_gas();

    batch_transfer(recipients).unwrap();

    let gas_used = gas_before - remaining_gas();
    assert!(gas_used < MAX_GAS_PER_BATCH);
}
```

## Deployment Checklist

### Pre-Deployment

- [ ] All unit tests pass
- [ ] Integration tests pass
- [ ] Fuzz tests run (1M+ iterations)
- [ ] Code reviewed by 2+ developers
- [ ] External audit completed (if applicable)
- [ ] Documentation complete
- [ ] Gas usage profiled
- [ ] Upgrade mechanism tested
- [ ] Emergency procedures documented

### Deployment

- [ ] Deploy to testnet first
- [ ] Test on testnet for 1+ week
- [ ] Verify contract bytecode
- [ ] Set correct permissions
- [ ] Initialize state properly
- [ ] Test emergency procedures
- [ ] Monitor for 24 hours
- [ ] Announce to community

### Post-Deployment

- [ ] Monitor gas usage
- [ ] Watch for unusual transactions
- [ ] Track error rates
- [ ] Collect user feedback
- [ ] Plan upgrades if needed
- [ ] Document any issues
- [ ] Maintain incident response plan

## Security Resources

### Tools

- **Static Analysis**: cargo-audit, clippy
- **Fuzz Testing**: cargo-fuzz, libFuzzer
- **Test Coverage**: cargo-tally
- **Gas Profiling**: MXD gas profiler

### Learning Resources

- [Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [SWC Registry](https://swcregistry.io/)
- [Trail of Bits Security Guide](https://github.com/crytic/building-secure-contracts)

### Getting Help

- **Discord**: #smart-contract-help
- **Email**: dev@mxdnetwork.com
- **Bug Bounty**: security@mxdnetwork.com

## Examples

### Secure Token Contract

```rust
pub struct Token {
    balances: Map<Address, u64>,
    total_supply: u64,
    paused: bool,
    owner: Address,
}

impl Token {
    pub fn transfer(&mut self, to: Address, amount: u64) -> Result<(), Error> {
        // Checks
        require(!self.paused)?;
        require(amount > 0)?;
        let sender = get_caller();
        let sender_balance = self.balances.get(&sender).unwrap_or(0);
        require(sender_balance >= amount)?;

        // Effects
        let new_sender_balance = sender_balance.checked_sub(amount)
            .ok_or(Error::Underflow)?;
        let recipient_balance = self.balances.get(&to).unwrap_or(0);
        let new_recipient_balance = recipient_balance.checked_add(amount)
            .ok_or(Error::Overflow)?;

        self.balances.insert(sender, new_sender_balance);
        self.balances.insert(to, new_recipient_balance);

        // Interactions (none for simple transfer)

        Ok(())
    }

    pub fn pause(&mut self) -> Result<(), Error> {
        require(get_caller() == self.owner)?;
        self.paused = true;
        Ok(())
    }
}
```

### Secure Auction Contract

```rust
pub struct Auction {
    highest_bid: u64,
    highest_bidder: Address,
    end_time: u64,
    ended: bool,
    pending_returns: Map<Address, u64>,
}

impl Auction {
    pub fn bid(&mut self, amount: u64) -> Result<(), Error> {
        // Checks
        require(block_timestamp() < self.end_time)?;
        require(amount > self.highest_bid)?;
        require(!self.ended)?;

        // Effects
        let sender = get_caller();

        // Refund previous highest bidder
        if self.highest_bidder != Address::zero() {
            let current = self.pending_returns.get(&self.highest_bidder).unwrap_or(0);
            self.pending_returns.insert(
                self.highest_bidder,
                current + self.highest_bid
            );
        }

        self.highest_bidder = sender;
        self.highest_bid = amount;

        Ok(())
    }

    pub fn withdraw(&mut self) -> Result<(), Error> {
        let sender = get_caller();
        let amount = self.pending_returns.get(&sender).unwrap_or(0);

        require(amount > 0)?;

        // Effects before interactions
        self.pending_returns.insert(sender, 0);

        // Interactions
        transfer(sender, amount)?;

        Ok(())
    }

    pub fn end_auction(&mut self) -> Result<(), Error> {
        require(block_timestamp() >= self.end_time)?;
        require(!self.ended)?;

        self.ended = true;

        // Transfer to auction creator
        transfer(get_owner(), self.highest_bid)?;

        Ok(())
    }
}
```

---

**Remember**: Security is not a feature, it's a process. Always prioritize security over convenience, and when in doubt, ask for help!

**Questions?** Contact security@mxdnetwork.com
