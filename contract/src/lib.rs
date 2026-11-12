//! Leash vault: on-chain spending limits and a kill switch for AI agents.
//!
//! The vault account holds the money. Each agent gets a Function Call Access
//! Key on the vault that may call one method, `pay`, and nothing else. Every
//! payment is checked against the agent's policy (per-payment cap, daily limit,
//! payment rate, receiver allowlist) and a shared scam blocklist. A payment that
//! breaks a rule is not sent: the agent is leashed and the vault deletes the
//! agent's key, so it cannot sign another transaction.
//!
//! Guardians (an off-chain watchdog, say) may leash an agent too, and may add
//! to the blocklist, but only the owner, a human, can release an agent. A
//! compromised watchdog can stop agents; it can never set one free.

use near_sdk::store::{IterableMap, IterableSet, LookupMap};
use near_sdk::{
    env, near, require, AccountId, Allowance, NearToken, PanicOnDefault, Promise, PublicKey,
};

const MINUTE_MS: u64 = 60_000;
const DAY_MS: u64 = 86_400_000;
const MAX_INCIDENTS: usize = 50;
const MAX_MEMO: usize = 140;

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub struct Policy {
    /// Largest single payment the agent may make.
    pub max_per_payment: NearToken,
    /// Total the agent may pay out per UTC day.
    pub daily_limit: NearToken,
    /// More payments than this inside 60 seconds looks like a loop.
    pub max_payments_per_minute: u32,
    /// When set, the agent may only pay these accounts.
    pub allowed_receivers: Option<Vec<AccountId>>,
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
pub struct PayOutcome {
    pub paid: bool,
    /// Set when the payment was refused and the agent leashed.
    pub leashed: Option<String>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct LeashVault {
    owner: AccountId,
    guardians: Vec<AccountId>,
    /// Gas allowance given to each agent key.
    key_allowance: NearToken,
    agents: IterableMap<String, Agent>,
    by_key: LookupMap<PublicKey, String>,
    blocklist: IterableSet<AccountId>,
    incidents: Vec<Incident>,
}

#[near]
impl LeashVault {
    #[init]
    pub fn new(owner: AccountId, guardians: Vec<AccountId>) -> Self {
        Self {
            owner,
            guardians,
            key_allowance: NearToken::from_millinear(250),
            agents: IterableMap::new(b"a"),
            by_key: LookupMap::new(b"k"),
            blocklist: IterableSet::new(b"b"),
            incidents: Vec::new(),
        }
    }

    // ----- agents -----

    /// Register an agent and give it a key that can only call `pay`.
    pub fn add_agent(&mut self, name: String, public_key: PublicKey, policy: Policy) {
        self.assert_owner();
        require!(!self.agents.contains_key(&name), "agent already exists");
        require!(!self.by_key.contains_key(&public_key), "key already belongs to an agent");
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

    pub fn remove_agent(&mut self, name: String) {
        self.assert_owner();
        let agent = self.agents.remove(&name).unwrap_or_else(|| env::panic_str("no such agent"));
        self.by_key.remove(&agent.public_key);
        if agent.leashed.is_none() {
            let _ = Promise::new(env::current_account_id()).delete_key(agent.public_key);
        }
    }

    // ----- payments -----

    /// Pay `amount` to `receiver_id`. Callable only with an agent's key.
    ///
    /// A payment that breaks the agent's policy is not sent; the agent is
    /// leashed and its key deleted instead. The call still succeeds, so the
    /// leash is recorded on-chain rather than rolled back.
    pub fn pay(&mut self, receiver_id: AccountId, amount: NearToken, memo: Option<String>) -> PayOutcome {
        require!(
            env::predecessor_account_id() == env::current_account_id(),
            "pay must be signed with an agent key"
        );
        let name = self
            .by_key
            .get(&env::signer_account_pk())
            .cloned()
            .unwrap_or_else(|| env::panic_str("unknown agent key"));
        require!(amount.as_yoctonear() > 0, "amount must be positive");
        require!(amount <= self.available(), "vault balance too low");
        let memo = memo.unwrap_or_default();
        require!(memo.len() <= MAX_MEMO, "memo too long");

        let now = env::block_timestamp_ms();
        let blocked = self.blocklist.contains(&receiver_id);
        let agent = self.agent_mut(&name);
        if let Some(reason) = &agent.leashed {
            env::panic_str(&format!("agent is leashed: {reason}"));
        }
        if agent.day != now / DAY_MS {
            agent.day = now / DAY_MS;
            agent.spent_today = NearToken::from_yoctonear(0);
        }
        agent.recent.retain(|t| now.saturating_sub(*t) < MINUTE_MS);

        let p = &agent.policy;
        let violation = if blocked {
            Some(format!("scam blocklist: {receiver_id} is flagged"))
        } else if p.allowed_receivers.as_ref().is_some_and(|r| !r.contains(&receiver_id)) {
            Some(format!("receiver not allowed: {receiver_id}"))
        } else if amount > p.max_per_payment {
            Some(format!("over per-payment cap: {} > {}", amount.exact_amount_display(), p.max_per_payment.exact_amount_display()))
        } else if agent.spent_today.saturating_add(amount) > p.daily_limit {
            Some(format!(
                "over daily limit: {} spent + {} > {}",
                agent.spent_today.exact_amount_display(),
                amount.exact_amount_display(),
                p.daily_limit.exact_amount_display()
            ))
        } else if agent.recent.len() as u32 >= p.max_payments_per_minute {
            Some(format!("payment loop: {} payments in the last minute", agent.recent.len() + 1))
        } else {
            None
        };

        if let Some(reason) = violation {
            self.trip(&name, reason.clone(), env::current_account_id());
            return PayOutcome { paid: false, leashed: Some(reason) };
        }

        agent.recent.push(now);
        agent.spent_today = agent.spent_today.saturating_add(amount);
        agent.total_spent = agent.total_spent.saturating_add(amount);
        agent.payments += 1;
        emit(
            "paid",
            &format!(
                r#"{{"agent":{},"receiver_id":"{}","amount":"{}","memo":{}}}"#,
                json_str(&name),
                receiver_id,
                amount.as_yoctonear(),
                json_str(&memo)
            ),
        );
        let _ = Promise::new(receiver_id).transfer(amount);
        PayOutcome { paid: true, leashed: None }
    }

    // ----- the leash -----

    /// Leash an agent now: freeze it and delete its key. Owner or guardian.
    pub fn leash(&mut self, name: String, reason: String) {
        let caller = env::predecessor_account_id();
        require!(caller == self.owner || self.guardians.contains(&caller), "only the owner or a guardian may leash");
        require!(reason.len() <= 300, "reason too long");
        self.agent_mut(&name);
        self.trip(&name, reason, caller);
    }

    /// Release a leashed agent. Owner only. Pass `new_public_key` to hand the
    /// agent a fresh key, so a stolen key stays dead.
    pub fn release(&mut self, name: String, new_public_key: Option<PublicKey>) {
        self.assert_owner();
        let agent = self.agent_mut(&name);
        let was = agent.leashed.take().unwrap_or_else(|| env::panic_str("agent is not leashed"));
        agent.leashed_by = None;
        agent.recent.clear();
        let old = agent.public_key.clone();
        let key = match new_public_key {
            Some(k) if k != old => {
                require!(!self.by_key.contains_key(&k), "key already belongs to an agent");
                self.by_key.remove(&old);
                self.by_key.insert(k.clone(), name.clone());
                self.agent_mut(&name).public_key = k.clone();
                k
            }
            _ => old,
        };
        self.log_incident(&name, "released", format!("released by the owner (was: {was})"), env::predecessor_account_id());
        self.grant_key(key);
    }

    /// Flag an account as a scam. Owner or guardian: guardians can only tighten.
    pub fn block_receiver(&mut self, account_id: AccountId) {
        let caller = env::predecessor_account_id();
        require!(caller == self.owner || self.guardians.contains(&caller), "only the owner or a guardian may block");
        self.blocklist.insert(account_id.clone());
        emit("blocked", &format!(r#"{{"account_id":"{account_id}","by":"{caller}"}}"#));
    }

    pub fn unblock_receiver(&mut self, account_id: AccountId) {
        self.assert_owner();
        self.blocklist.remove(&account_id);
    }

    pub fn set_guardians(&mut self, guardians: Vec<AccountId>) {
        self.assert_owner();
        self.guardians = guardians;
    }

    /// Send vault funds back to the owner.
    pub fn withdraw(&mut self, amount: NearToken) -> Promise {
        self.assert_owner();
        require!(amount <= self.available(), "vault balance too low");
        Promise::new(self.owner.clone()).transfer(amount)
    }

    // ----- views -----

    pub fn get_agents(&self) -> Vec<&Agent> {
        self.agents.values().collect()
    }

    pub fn get_agent(&self, name: String) -> Option<&Agent> {
        self.agents.get(&name)
    }

    pub fn get_incidents(&self) -> &Vec<Incident> {
        &self.incidents
    }

    pub fn get_blocklist(&self) -> Vec<&AccountId> {
        self.blocklist.iter().collect()
    }

    pub fn get_config(&self) -> (AccountId, Vec<AccountId>, NearToken) {
        (self.owner.clone(), self.guardians.clone(), self.available())
    }

    // ----- internals -----

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
            &format!(r#"{{"agent":{},"reason":{},"by":"{}"}}"#, json_str(agent), json_str(&reason), by),
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
            "pay".to_string(),
        );
    }

    fn agent_mut(&mut self, name: &str) -> &mut Agent {
        self.agents.get_mut(name).unwrap_or_else(|| env::panic_str("no such agent"))
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "only the owner may do this");
    }

    /// Balance not locked for storage.
    fn available(&self) -> NearToken {
        let locked = env::storage_byte_cost().saturating_mul(env::storage_usage() as u128);
        env::account_balance().saturating_sub(locked)
    }
}

fn check_policy(p: &Policy) {
    require!(p.max_per_payment <= p.daily_limit, "max_per_payment exceeds daily_limit");
    require!(p.max_payments_per_minute > 0, "max_payments_per_minute must be positive");
}

fn today() -> u64 {
    env::block_timestamp_ms() / DAY_MS
}

/// Log a NEP-297 event.
fn emit(event: &str, data: &str) {
    env::log_str(&format!(
        r#"EVENT_JSON:{{"standard":"leash","version":"1.0.0","event":"{event}","data":[{data}]}}"#
    ));
}

fn json_str(s: &str) -> String {
    near_sdk::serde_json::to_string(s).unwrap()
}

#[cfg(test)]
mod tests;
