use super::*;
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::{testing_env, CurveType};

fn acct(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn vault() -> AccountId {
    acct("vault.testnet")
}

fn owner() -> AccountId {
    acct("owner.testnet")
}

fn watchdog() -> AccountId {
    acct("watchdog.testnet")
}

fn key(n: u8) -> PublicKey {
    PublicKey::from_parts(CurveType::ED25519, vec![n; 32]).unwrap()
}

fn near(n: u128) -> NearToken {
    NearToken::from_near(n)
}

fn milli(n: u128) -> NearToken {
    NearToken::from_millinear(n)
}

fn policy() -> Policy {
    Policy {
        max_per_payment: milli(500),
        daily_limit: near(2),
        max_payments_per_minute: 3,
        allowed_receivers: None,
    }
}

/// Set the context: `caller` calls the vault at time `ms`, signing with `pk`.
fn ctx(caller: AccountId, pk: PublicKey, ms: u64) {
    testing_env!(VMContextBuilder::new()
        .current_account_id(vault())
        .predecessor_account_id(caller.clone())
        .signer_account_id(caller)
        .signer_account_pk(pk)
        .block_timestamp(ms * 1_000_000)
        .account_balance(near(100))
        .build());
}

fn as_owner() {
    ctx(owner(), key(200), 1_000)
}

fn as_agent(n: u8, ms: u64) {
    ctx(vault(), key(n), ms)
}

fn setup() -> LeashVault {
    as_owner();
    let mut v = LeashVault::new(owner(), vec![watchdog()]);
    v.add_agent("shopper".into(), key(1), policy());
    v.add_agent("researcher".into(), key(2), policy());
    v
}

fn leashed(v: &LeashVault, name: &str) -> Option<String> {
    v.get_agent(name.into()).unwrap().leashed.clone()
}

#[test]
fn pays_within_policy() {
    let mut v = setup();
    as_agent(1, 2_000);
    let out = v.pay(acct("api.testnet"), milli(200), Some("100 search calls".into()));
    assert_eq!(out, PayOutcome { paid: true, leashed: None });
    let a = v.get_agent("shopper".into()).unwrap();
    assert_eq!(a.spent_today, milli(200));
    assert_eq!(a.payments, 1);
    assert!(get_logs().iter().any(|l| l.contains(r#""event":"paid""#)));
}

#[test]
#[should_panic(expected = "pay must be signed with an agent key")]
fn pay_rejects_other_callers() {
    let mut v = setup();
    ctx(acct("mallory.testnet"), key(1), 2_000);
    v.pay(acct("api.testnet"), milli(1), None);
}

#[test]
#[should_panic(expected = "unknown agent key")]
fn pay_rejects_unknown_keys() {
    let mut v = setup();
    as_agent(99, 2_000);
    v.pay(acct("api.testnet"), milli(1), None);
}

#[test]
fn over_cap_payment_leashes_the_agent() {
    let mut v = setup();
    as_agent(1, 2_000);
    let out = v.pay(acct("api.testnet"), near(1), None);
    assert!(!out.paid);
    assert!(out.leashed.unwrap().starts_with("over per-payment cap"));
    assert!(leashed(&v, "shopper").is_some());
    assert_eq!(v.get_agent("shopper".into()).unwrap().spent_today, milli(0));
    assert!(leashed(&v, "researcher").is_none(), "other agents keep running");
    assert_eq!(v.get_incidents().len(), 1);
}

#[test]
fn daily_limit_leashes_the_agent() {
    let mut v = setup();
    for (i, ms) in [2_000, 70_000, 140_000, 210_000].iter().enumerate() {
        as_agent(1, *ms);
        assert!(v.pay(acct("api.testnet"), milli(500), None).paid, "payment {i}");
    }
    as_agent(1, 280_000);
    let out = v.pay(acct("api.testnet"), milli(1), None);
    assert!(out.leashed.unwrap().starts_with("over daily limit"));
}

#[test]
fn daily_limit_resets_the_next_day() {
    let mut v = setup();
    as_agent(1, 2_000);
    v.pay(acct("api.testnet"), milli(500), None);
    as_agent(1, DAY_MS + 2_000);
    v.pay(acct("api.testnet"), milli(100), None);
    assert_eq!(v.get_agent("shopper".into()).unwrap().spent_today, milli(100));
}

#[test]
fn rapid_payments_look_like_a_loop() {
    let mut v = setup();
    for ms in [2_000, 3_000, 4_000] {
        as_agent(1, ms);
        assert!(v.pay(acct("api.testnet"), milli(10), None).paid);
    }
    as_agent(1, 5_000);
    let out = v.pay(acct("api.testnet"), milli(10), None);
    assert!(out.leashed.unwrap().starts_with("payment loop"));
}

#[test]
fn blocklisted_receiver_leashes_the_agent() {
    let mut v = setup();
    ctx(watchdog(), key(201), 1_500);
    v.block_receiver(acct("drainer.testnet"));
    as_agent(1, 2_000);
    let out = v.pay(acct("drainer.testnet"), milli(1), None);
    assert!(out.leashed.unwrap().starts_with("scam blocklist"));
}

#[test]
fn allowlist_is_enforced() {
    let mut v = setup();
    as_owner();
    v.set_policy("shopper".into(), Policy { allowed_receivers: Some(vec![acct("api.testnet")]), ..policy() });
    as_agent(1, 2_000);
    assert!(v.pay(acct("api.testnet"), milli(1), None).paid);
    as_agent(1, 3_000);
    assert!(v.pay(acct("other.testnet"), milli(1), None).leashed.unwrap().starts_with("receiver not allowed"));
}

#[test]
#[should_panic(expected = "agent is leashed")]
fn leashed_agent_cannot_pay() {
    let mut v = setup();
    ctx(watchdog(), key(201), 1_500);
    v.leash("shopper".into(), "prompt injection".into());
    as_agent(1, 2_000);
    v.pay(acct("api.testnet"), milli(1), None);
}

#[test]
fn guardian_can_leash() {
    let mut v = setup();
    ctx(watchdog(), key(201), 1_500);
    v.leash("shopper".into(), "dangerous tool call".into());
    let a = v.get_agent("shopper".into()).unwrap();
    assert_eq!(a.leashed.as_deref(), Some("dangerous tool call"));
    assert_eq!(a.leashed_by, Some(watchdog()));
}

#[test]
#[should_panic(expected = "only the owner may do this")]
fn guardian_cannot_release() {
    let mut v = setup();
    ctx(watchdog(), key(201), 1_500);
    v.leash("shopper".into(), "dangerous tool call".into());
    v.release("shopper".into(), None);
}

#[test]
#[should_panic(expected = "only the owner or a guardian may leash")]
fn strangers_cannot_leash() {
    let mut v = setup();
    ctx(acct("mallory.testnet"), key(9), 1_500);
    v.leash("shopper".into(), "griefing".into());
}

#[test]
fn owner_releases_with_a_fresh_key() {
    let mut v = setup();
    ctx(watchdog(), key(201), 1_500);
    v.leash("shopper".into(), "key leaked".into());
    as_owner();
    v.release("shopper".into(), Some(key(7)));
    assert!(leashed(&v, "shopper").is_none());
    as_agent(7, 2_000);
    assert!(v.pay(acct("api.testnet"), milli(1), None).paid);
    assert_eq!(v.get_incidents().last().unwrap().kind, "released");
}

#[test]
#[should_panic(expected = "unknown agent key")]
fn old_key_is_dead_after_rotation() {
    let mut v = setup();
    ctx(watchdog(), key(201), 1_500);
    v.leash("shopper".into(), "key leaked".into());
    as_owner();
    v.release("shopper".into(), Some(key(7)));
    as_agent(1, 2_000);
    v.pay(acct("api.testnet"), milli(1), None);
}

#[test]
fn incidents_are_capped() {
    let mut v = setup();
    for i in 0..(MAX_INCIDENTS + 5) {
        ctx(watchdog(), key(201), 1_500);
        v.leash("shopper".into(), format!("trip {i}"));
        as_owner();
        v.release("shopper".into(), None);
    }
    assert_eq!(v.get_incidents().len(), MAX_INCIDENTS);
}

#[test]
#[should_panic(expected = "max_per_payment exceeds daily_limit")]
fn rejects_inconsistent_policy() {
    let mut v = setup();
    as_owner();
    v.set_policy("shopper".into(), Policy { max_per_payment: near(5), ..policy() });
}
