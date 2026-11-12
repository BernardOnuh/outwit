//! Outwit vault: an AI agent's wallet where nothing moves without a second opinion.
//!
//! The vault holds the money. The agent gets a Function Call Access Key that can
//! call one method, `propose`, and nothing else: it can ask to pay, never pay.
//! A guard (the Outwit firewall) vets each proposal and calls `approve` or
//! `reject`, so every verdict and its reason are on-chain. Money moves only when
//! the agent proposed it AND a guard approved it, and only within the owner's
//! hard limits, which the contract enforces on its own:
//!
//! - per-payment cap, daily limit and proposal rate per agent;
//! - a payee list the owner keeps, and invoices that only payees can raise;
//! - a scam blocklist guards can add to but only the owner can shrink.
//!
//! A proposal that breaks a hard limit is refused and the agent leashed: its key
//! is deleted, so it cannot sign again until the owner, a human, releases it.

use near_sdk::store::{IterableMap, IterableSet, LookupMap, Vector};
use near_sdk::{
    env, near, require, AccountId, Allowance, NearToken, PanicOnDefault, Promise, PublicKey,
};

const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 86_400_000;
const PROPOSAL_TTL_MS: u64 = 15 * MINUTE_MS;
const MAX_INCIDENTS: usize = 50;
const MAX_TEXT: usize = 280;

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// Largest single payment the agent may propose.
    pub max_per_payment: NearToken,
    /// Total the agent may pay out per UTC day.
    pub daily_limit: NearToken,
    /// More proposals than this inside 60 seconds looks like a loop.
    pub max_proposals_per_minute: u32,
    /// When true, the agent may only pay accounts on the payee list.
    pub payees_only: bool,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Agent {
    pub name: String,
    pub public_key: PublicKey,
    pub policy: Policy,
    /// Why the agent is leashed; `None` while it is active.
    pub leashed: Option<String>,
    pub leashed_by: Option<AccountId>,
    pub day: u64,
    pub spent_today: NearToken,
    pub total_spent: NearToken,
    pub payments: u64,
    recent: Vec<u64>,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Payee {
    pub account_id: AccountId,
    pub label: String,
    pub added_ms: u64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub enum InvoiceStatus {
    Open,
    Paid,
    Cancelled,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Invoice {
    pub id: u64,
    /// The payee that raised it, and the only account it can be paid to.
    pub payee: AccountId,
    pub amount: NearToken,
    pub memo: String,
    pub status: InvoiceStatus,
    pub created_ms: u64,
    pub paid_by: Option<u64>,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalStatus {
    /// Waiting for a guard.
    Pending,
    /// Approved by a guard and sent.
    Paid,
    /// A guard said no.
    Rejected,
    /// Broke a hard limit; the agent was leashed.
    Refused,
    /// No guard decided in time, or it no longer fit the limits when one did.
    Expired,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub agent: String,
    pub receiver_id: AccountId,
    pub amount: NearToken,
    pub invoice_id: Option<u64>,
    pub memo: String,
    pub status: ProposalStatus,
    pub reason: Option<String>,
    pub decided_by: Option<AccountId>,
    pub created_ms: u64,
    pub decided_ms: Option<u64>,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct Incident {
    pub agent: String,
    /// "leashed" or "released".
    pub kind: String,
    pub reason: String,
    pub by: AccountId,
    pub at_ms: u64,
}

#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub struct ProposeOutcome {
    pub id: u64,
    pub status: ProposalStatus,
    pub reason: Option<String>,
}

#[near(serializers = [json])]
pub struct Config {
    pub owner: AccountId,
    pub guards: Vec<AccountId>,
    pub available: NearToken,
    pub proposals: u64,
    pub invoices: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct OutwitVault {
    owner: AccountId,
    guards: Vec<AccountId>,
    key_allowance: NearToken,
    agents: IterableMap<String, Agent>,
    by_key: LookupMap<PublicKey, String>,
    payees: IterableMap<AccountId, Payee>,
    blocklist: IterableSet<AccountId>,
    invoices: Vector<Invoice>,
    proposals: Vector<Proposal>,
    incidents: Vec<Incident>,
}

#[near]
impl OutwitVault {
    #[init]
    pub fn new(owner: AccountId, guards: Vec<AccountId>) -> Self {
        Self {
            owner,
            guards,
            key_allowance: NearToken::from_millinear(250),
            agents: IterableMap::new(b"a"),
            by_key: LookupMap::new(b"k"),
            payees: IterableMap::new(b"p"),
            blocklist: IterableSet::new(b"b"),
            invoices: Vector::new(b"i"),
            proposals: Vector::new(b"q"),
            incidents: Vec::new(),
        }
    }

    // ----- owner setup -----

    /// Register an agent and give it a key that can only call `propose`.
    pub fn add_agent(&mut self, name: String, public_key: PublicKey, policy: Policy) {
        self.assert_owner();
        require!(!self.agents.contains_key(&name), "agent already exists");
        require!(
            !self.by_key.contains_key(&public_key),
            "key already belongs to an agent"
        );
        check_policy(&policy);
        self.by_key.insert(public_key.clone(), name.clone());
        self.agents.insert(
            name.clone(),
            Agent {
                name,
                public_key: public_key.clone(),
                policy,
                leashed: None,
                leashed_by: None,
                day: today(),
                spent_today: NearToken::from_yoctonear(0),
                total_spent: NearToken::from_yoctonear(0),
                payments: 0,
                recent: Vec::new(),
            },
        );
        self.grant_key(public_key);
    }

    pub fn set_policy(&mut self, name: String, policy: Policy) {
        self.assert_owner();
        check_policy(&policy);
        self.agent_mut(&name).policy = policy;
    }

    pub fn add_payee(&mut self, account_id: AccountId, label: String) {
        self.assert_owner();
        require!(label.len() <= 64, "label too long");
        let payee = Payee {
            account_id: account_id.clone(),
            label,
            added_ms: env::block_timestamp_ms(),
        };
        self.payees.insert(account_id, payee);
    }

    pub fn remove_payee(&mut self, account_id: AccountId) {
        self.assert_owner();
        self.payees.remove(&account_id);
    }

    pub fn set_guards(&mut self, guards: Vec<AccountId>) {
        self.assert_owner();
        self.guards = guards;
    }

    /// Send vault funds back to the owner.
    pub fn withdraw(&mut self, amount: NearToken) -> Promise {
        self.assert_owner();
        require!(amount <= self.available(), "vault balance too low");
        Promise::new(self.owner.clone()).transfer(amount)
    }

    // ----- invoices -----

    /// Raise an invoice. Only an approved payee can, and only to itself, so an
    /// invoice is proof that the account being paid asked to be paid.
    pub fn create_invoice(&mut self, amount: NearToken, memo: String) -> u64 {
        let payee = env::predecessor_account_id();
        require!(
            self.payees.contains_key(&payee),
            "only approved payees can raise invoices"
        );
        require!(amount.as_yoctonear() > 0, "amount must be positive");
        require!(memo.len() <= MAX_TEXT, "memo too long");
        let id = self.invoices.len() as u64;
        self.invoices.push(Invoice {
            id,
            payee: payee.clone(),
            amount,
            memo: memo.clone(),
            status: InvoiceStatus::Open,
            created_ms: env::block_timestamp_ms(),
            paid_by: None,
        });
        emit(
            "invoice",
            &format!(
                r#"{{"id":{id},"payee":"{payee}","amount":"{}","memo":{}}}"#,
                amount.as_yoctonear(),
                json_str(&memo)
            ),
        );
        id
    }

    /// Cancel an open invoice: the payee that raised it, or the owner.
    pub fn cancel_invoice(&mut self, id: u64) {
        let caller = env::predecessor_account_id();
        let owner = self.owner.clone();
        let inv = self
            .invoices
            .get_mut(id as u32)
            .unwrap_or_else(|| env::panic_str("no such invoice"));
        require!(
            caller == inv.payee || caller == owner,
            "only the payee or the owner may cancel"
        );
        require!(inv.status == InvoiceStatus::Open, "invoice is not open");
        inv.status = InvoiceStatus::Cancelled;
    }

    // ----- the agent asks -----

    /// Ask to pay `amount` to `receiver_id`. Callable only with an agent's key.
    /// Hard limits are checked here; anything that passes waits for a guard.
    pub fn propose(
        &mut self,
        receiver_id: AccountId,
        amount: NearToken,
        invoice_id: Option<u64>,
        memo: Option<String>,
    ) -> ProposeOutcome {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "propose must be signed with an agent key"
        );
        let name = self
            .by_key
            .get(&env::signer_account_pk())
            .cloned()
            .unwrap_or_else(|| env::panic_str("unknown agent key"));
        require!(amount.as_yoctonear() > 0, "amount must be positive");
        let memo = memo.unwrap_or_default();
        require!(memo.len() <= MAX_TEXT, "memo too long");
        if let Some(i) = invoice_id {
            require!((i as u32) < self.invoices.len(), "no such invoice");
        }

        let now = env::block_timestamp_ms();
        let blocked = self.blocklist.contains(&receiver_id);
        let is_payee = self.payees.contains_key(&receiver_id);
        let agent = self.agent_mut(&name);
        if let Some(reason) = &agent.leashed {
            env::panic_str(&format!("agent is leashed: {reason}"));
        }
        roll_day(agent, now);
        agent.recent.retain(|t| now.saturating_sub(*t) < MINUTE_MS);
        let p = &agent.policy;
        let violation = if blocked {
            Some(format!("scam blocklist: {receiver_id} is flagged"))
        } else if p.payees_only && !is_payee {
            Some(format!("not an approved payee: {receiver_id}"))
        } else if amount > p.max_per_payment {
            Some(format!(
                "over per-payment cap: {} > {}",
                amount.exact_amount_display(),
                p.max_per_payment.exact_amount_display()
            ))
        } else if agent.spent_today.saturating_add(amount) > p.daily_limit {
            Some(format!(
                "over daily limit: {} spent + {} > {}",
                agent.spent_today.exact_amount_display(),
                amount.exact_amount_display(),
                p.daily_limit.exact_amount_display()
            ))
        } else if agent.recent.len() as u32 >= p.max_proposals_per_minute {
            Some(format!(
                "proposal loop: {} proposals in the last minute",
                agent.recent.len() + 1
            ))
        } else {
            None
        };
        if violation.is_none() {
            agent.recent.push(now);
        }

        let id = self.proposals.len() as u64;
        let status = if violation.is_some() {
            ProposalStatus::Refused
        } else {
            ProposalStatus::Pending
        };
        self.proposals.push(Proposal {
            id,
            agent: name.clone(),
            receiver_id: receiver_id.clone(),
            amount,
            invoice_id,
            memo: memo.clone(),
            status: status.clone(),
            reason: violation.clone(),
            decided_by: violation.as_ref().map(|_| env::current_account_id()),
            created_ms: now,
            decided_ms: violation.as_ref().map(|_| now),
        });
        emit(
            "proposed",
            &format!(
                r#"{{"id":{id},"agent":{},"receiver_id":"{receiver_id}","amount":"{}","invoice_id":{},"memo":{}}}"#,
                json_str(&name),
                amount.as_yoctonear(),
                invoice_id.map_or("null".to_string(), |i| i.to_string()),
                json_str(&memo)
            ),
        );
        if let Some(reason) = &violation {
            self.trip(&name, reason.clone(), env::current_account_id());
        }
        ProposeOutcome {
            id,
            status,
            reason: violation,
        }
    }

    // ----- the guard decides -----

    /// Approve a pending proposal and send the money. Guards only. The hard
    /// limits are checked again, since time has passed since the proposal.
    pub fn approve(&mut self, id: u64, reason: Option<String>) -> ProposalStatus {
        let guard = self.assert_guard();
        let now = env::block_timestamp_ms();
        let prop = self.pending(id);
        let reason = reason.unwrap_or_else(|| "approved".to_string());
        require!(reason.len() <= MAX_TEXT, "reason too long");

        let mut problem = None;
        if now.saturating_sub(prop.created_ms) > PROPOSAL_TTL_MS {
            problem = Some("expired: no guard decided within 15 minutes".to_string());
        } else if prop.amount > self.available() {
            problem = Some("vault balance too low".to_string());
        } else if self.blocklist.contains(&prop.receiver_id) {
            problem = Some(format!("scam blocklist: {} is flagged", prop.receiver_id));
        }
        if let Some(inv_id) = prop.invoice_id {
            let inv = self.invoices.get(inv_id as u32).unwrap();
            if inv.status != InvoiceStatus::Open {
                problem = problem.or(Some(format!("invoice {inv_id} is not open")));
            } else if inv.payee != prop.receiver_id || inv.amount != prop.amount {
                problem = problem.or(Some(format!("does not match invoice {inv_id}")));
            }
        }
        {
            let agent = self.agent_mut(&prop.agent);
            roll_day(agent, now);
            if agent.leashed.is_some() {
                problem = problem.or(Some("agent is leashed".to_string()));
            } else if agent.spent_today.saturating_add(prop.amount) > agent.policy.daily_limit {
                problem = problem.or(Some("over daily limit at approval".to_string()));
            }
        }
        if let Some(problem) = problem {
            self.decide(id, ProposalStatus::Expired, problem, guard);
            return ProposalStatus::Expired;
        }

        let agent = self.agent_mut(&prop.agent);
        agent.spent_today = agent.spent_today.saturating_add(prop.amount);
        agent.total_spent = agent.total_spent.saturating_add(prop.amount);
        agent.payments += 1;
        if let Some(inv_id) = prop.invoice_id {
            let inv = self.invoices.get_mut(inv_id as u32).unwrap();
            inv.status = InvoiceStatus::Paid;
            inv.paid_by = Some(id);
        }
        self.decide(id, ProposalStatus::Paid, reason, guard);
        let _ = Promise::new(prop.receiver_id).transfer(prop.amount);
        ProposalStatus::Paid
    }

    /// Reject a pending proposal, with the reason on record. Guards only.
    pub fn reject(&mut self, id: u64, reason: String) {
        let guard = self.assert_guard();
        self.pending(id);
        require!(reason.len() <= MAX_TEXT, "reason too long");
        self.decide(id, ProposalStatus::Rejected, reason, guard);
    }

    // ----- the leash -----

    /// Leash an agent now: freeze it and delete its key. Owner or guard.
    pub fn leash(&mut self, name: String, reason: String) {
        let caller = self.assert_guard();
        require!(reason.len() <= MAX_TEXT, "reason too long");
        self.agent_mut(&name);
        self.trip(&name, reason, caller);
    }

    /// Release a leashed agent. Owner only. Pass `new_public_key` to hand the
    /// agent a fresh key, so a stolen key stays dead.
    pub fn release(&mut self, name: String, new_public_key: Option<PublicKey>) {
        self.assert_owner();
        let agent = self.agent_mut(&name);
        let was = agent
            .leashed
            .take()
            .unwrap_or_else(|| env::panic_str("agent is not leashed"));
        agent.leashed_by = None;
        agent.recent.clear();
        let old = agent.public_key.clone();
        let key = match new_public_key {
            Some(k) if k != old => {
                require!(
                    !self.by_key.contains_key(&k),
                    "key already belongs to an agent"
                );
                self.by_key.remove(&old);
                self.by_key.insert(k.clone(), name.clone());
                self.agent_mut(&name).public_key = k.clone();
                k
            }
            _ => old,
        };
        self.log_incident(
            &name,
            "released",
            format!("released by the owner (was: {was})"),
            env::predecessor_account_id(),
        );
        self.grant_key(key);
    }

    /// Flag an account as a scam. Owner or guard: guards can only tighten.
    pub fn block_receiver(&mut self, account_id: AccountId) {
        let caller = self.assert_guard();
        self.blocklist.insert(account_id.clone());
        emit(
            "blocked",
            &format!(r#"{{"account_id":"{account_id}","by":"{caller}"}}"#),
        );
    }

    pub fn unblock_receiver(&mut self, account_id: AccountId) {
        self.assert_owner();
        self.blocklist.remove(&account_id);
    }

    // ----- views -----

    pub fn get_config(&self) -> Config {
        Config {
            owner: self.owner.clone(),
            guards: self.guards.clone(),
            available: self.available(),
            proposals: self.proposals.len() as u64,
            invoices: self.invoices.len() as u64,
        }
    }

    pub fn get_agents(&self) -> Vec<&Agent> {
        self.agents.values().collect()
    }

    pub fn get_agent(&self, name: String) -> Option<&Agent> {
        self.agents.get(&name)
    }

    pub fn get_payees(&self) -> Vec<&Payee> {
        self.payees.values().collect()
    }

    pub fn get_invoices(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<&Invoice> {
        page(&self.invoices, from_index, limit)
    }

    pub fn get_invoice(&self, id: u64) -> Option<&Invoice> {
        self.invoices.get(id as u32)
    }

    pub fn get_proposals(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<&Proposal> {
        page(&self.proposals, from_index, limit)
    }

    pub fn get_proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(id as u32)
    }

    /// Pending proposals among the newest `scan` (default 100).
    pub fn get_pending(&self, scan: Option<u64>) -> Vec<&Proposal> {
        let n = self.proposals.len() as u64;
        let from = n.saturating_sub(scan.unwrap_or(100));
        (from..n)
            .filter_map(|i| self.proposals.get(i as u32))
            .filter(|p| p.status == ProposalStatus::Pending)
            .collect()
    }

    pub fn get_incidents(&self) -> &Vec<Incident> {
        &self.incidents
    }

    pub fn get_blocklist(&self) -> Vec<&AccountId> {
        self.blocklist.iter().collect()
    }

    // ----- internals -----

    fn pending(&self, id: u64) -> Proposal {
        let prop = self
            .proposals
            .get(id as u32)
            .unwrap_or_else(|| env::panic_str("no such proposal"));
        require!(
            prop.status == ProposalStatus::Pending,
            "proposal is not pending"
        );
        prop.clone()
    }

    fn decide(&mut self, id: u64, status: ProposalStatus, reason: String, by: AccountId) {
        let prop = self.proposals.get_mut(id as u32).unwrap();
        let event = match status {
            ProposalStatus::Paid => "paid",
            ProposalStatus::Rejected => "rejected",
            _ => "expired",
        };
        prop.status = status;
        prop.reason = Some(reason.clone());
        prop.decided_by = Some(by.clone());
        prop.decided_ms = Some(env::block_timestamp_ms());
        emit(
            event,
            &format!(
                r#"{{"id":{id},"by":"{by}","reason":{}}}"#,
                json_str(&reason)
            ),
        );
    }

    fn trip(&mut self, name: &str, reason: String, by: AccountId) {
        let agent = self.agent_mut(name);
        if agent.leashed.is_some() {
            return;
        }
        agent.leashed = Some(reason.clone());
        agent.leashed_by = Some(by.clone());
        let key = agent.public_key.clone();
        self.log_incident(name, "leashed", reason, by);
        // The key goes in a separate receipt, so the leash above stands even
        // if the key is already gone.
        let _ = Promise::new(env::current_account_id()).delete_key(key);
    }

    fn log_incident(&mut self, agent: &str, kind: &str, reason: String, by: AccountId) {
        emit(
            kind,
            &format!(
                r#"{{"agent":{},"reason":{},"by":"{}"}}"#,
                json_str(agent),
                json_str(&reason),
                by
            ),
        );
        if self.incidents.len() >= MAX_INCIDENTS {
            self.incidents.remove(0);
        }
        self.incidents.push(Incident {
            agent: agent.to_string(),
            kind: kind.to_string(),
            reason,
            by,
            at_ms: env::block_timestamp_ms(),
        });
    }

    fn grant_key(&self, public_key: PublicKey) {
        let allowance = Allowance::limited(self.key_allowance).unwrap_or(Allowance::Unlimited);
        let _ = Promise::new(env::current_account_id()).add_access_key_allowance(
            public_key,
            allowance,
            env::current_account_id(),
            "propose".to_string(),
        );
    }

    fn agent_mut(&mut self, name: &str) -> &mut Agent {
        self.agents
            .get_mut(name)
            .unwrap_or_else(|| env::panic_str("no such agent"))
    }

    fn assert_owner(&self) {
        require!(
            env::predecessor_account_id() == self.owner,
            "only the owner may do this"
        );
    }

    fn assert_guard(&self) -> AccountId {
        let caller = env::predecessor_account_id();
        require!(
            caller == self.owner || self.guards.contains(&caller),
            "only the owner or a guard may do this"
        );
        caller
    }

    /// Balance not locked for storage.
    fn available(&self) -> NearToken {
        let locked = env::storage_byte_cost().saturating_mul(env::storage_usage() as u128);
        env::account_balance().saturating_sub(locked)
    }
}

fn page<T: near_sdk::borsh::BorshSerialize + near_sdk::borsh::BorshDeserialize>(
    v: &Vector<T>,
    from_index: Option<u64>,
    limit: Option<u64>,
) -> Vec<&T> {
    let n = v.len() as u64;
    let limit = limit.unwrap_or(50).min(100);
    // Newest first by default.
    let start = from_index.unwrap_or(n.saturating_sub(limit));
    (start..n.min(start + limit))
        .rev()
        .filter_map(|i| v.get(i as u32))
        .collect()
}

fn roll_day(agent: &mut Agent, now: u64) {
    if agent.day != now / DAY_MS {
        agent.day = now / DAY_MS;
        agent.spent_today = NearToken::from_yoctonear(0);
    }
}

fn check_policy(p: &Policy) {
    require!(
        p.max_per_payment <= p.daily_limit,
        "max_per_payment exceeds daily_limit"
    );
    require!(
        p.max_proposals_per_minute > 0,
        "max_proposals_per_minute must be positive"
    );
}

fn today() -> u64 {
    env::block_timestamp_ms() / DAY_MS
}

/// Log a NEP-297 event.
fn emit(event: &str, data: &str) {
    env::log_str(&format!(
        r#"EVENT_JSON:{{"standard":"outwit","version":"1.0.0","event":"{event}","data":[{data}]}}"#
    ));
}

fn json_str(s: &str) -> String {
    near_sdk::serde_json::to_string(s).unwrap()
}

#[cfg(test)]
mod tests;
