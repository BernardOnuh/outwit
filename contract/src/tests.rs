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

fn guard() -> AccountId {
    acct("outwit.testnet")
}

fn vendor() -> AccountId {
    acct("inkwell.testnet")
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
        max_proposals_per_minute: 3,
        payees_only: false,
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

fn as_guard(ms: u64) {
    ctx(guard(), key(201), ms)
}

fn as_agent(n: u8, ms: u64) {
    ctx(vault(), key(n), ms)
}

fn setup() -> OutwitVault {
    as_owner();
    let mut v = OutwitVault::new(owner(), vec![guard()]);
    v.add_agent("keeper".into(), key(1), policy());
    v.add_agent("buyer".into(), key(2), policy());
    v.add_payee(vendor(), "Inkwell Design".into());
    v
}

fn invoice(v: &mut OutwitVault, amount: NearToken) -> u64 {
    ctx(vendor(), key(50), 1_500);
    v.create_invoice(amount, "logo work".into())
}

fn status(v: &OutwitVault, id: u64) -> ProposalStatus {
    v.get_proposal(id).unwrap().status.clone()
}

fn leashed(v: &OutwitVault, name: &str) -> Option<String> {
    v.get_agent(name.into()).unwrap().leashed.clone()
}

#[test]
fn proposal_waits_for_the_guard_then_pays_the_invoice() {
    let mut v = setup();
    let inv = invoice(&mut v, milli(200));
    as_agent(1, 2_000);
    let out = v.propose(vendor(), milli(200), Some(inv), Some("INV logo".into()));
    assert_eq!(out.status, ProposalStatus::Pending);
    assert_eq!(v.get_pending(None).len(), 1);
    assert_eq!(
        v.get_agent("keeper".into()).unwrap().spent_today,
        milli(0),
        "nothing moves on a proposal"
    );

    as_guard(3_000);
    assert_eq!(
        v.approve(out.id, Some("matches invoice".into())),
        ProposalStatus::Paid
    );
    assert_eq!(status(&v, out.id), ProposalStatus::Paid);
    assert_eq!(v.get_invoice(inv).unwrap().status, InvoiceStatus::Paid);
    assert_eq!(
        v.get_agent("keeper".into()).unwrap().spent_today,
        milli(200)
    );
    assert!(get_logs().iter().any(|l| l.contains(r#""event":"paid""#)));
    assert!(v.get_pending(None).is_empty());
}

#[test]
fn guard_rejection_is_recorded_with_its_reason() {
    let mut v = setup();
    as_agent(1, 2_000);
    let out = v.propose(acct("mallory.testnet"), milli(100), None, None);
    as_guard(3_000);
    v.reject(
        out.id,
        "requester_paid: the money would go to the person asking".into(),
    );
    let p = v.get_proposal(out.id).unwrap();
    assert_eq!(p.status, ProposalStatus::Rejected);
    assert_eq!(p.decided_by, Some(guard()));
    assert!(p.reason.as_ref().unwrap().starts_with("requester_paid"));
    assert!(
        leashed(&v, "keeper").is_none(),
        "a rejection alone does not leash"
    );
}

#[test]
#[should_panic(expected = "only the owner or a guard may do this")]
fn agents_cannot_approve_their_own_proposals() {
    let mut v = setup();
    as_agent(1, 2_000);
    let out = v.propose(acct("mallory.testnet"), milli(100), None, None);
    ctx(acct("mallory.testnet"), key(9), 2_500);
    v.approve(out.id, None);
}

#[test]
#[should_panic(expected = "proposal is not pending")]
fn a_proposal_is_decided_once() {
    let mut v = setup();
    as_agent(1, 2_000);
    let out = v.propose(acct("x.testnet"), milli(100), None, None);
    as_guard(3_000);
    v.reject(out.id, "no".into());
    v.approve(out.id, None);
}

#[test]
#[should_panic(expected = "propose must be signed with an agent key")]
fn propose_rejects_other_callers() {
    let mut v = setup();
    ctx(acct("mallory.testnet"), key(1), 2_000);
    v.propose(acct("x.testnet"), milli(1), None, None);
}

#[test]
#[should_panic(expected = "unknown agent key")]
fn propose_rejects_unknown_keys() {
    let mut v = setup();
    as_agent(99, 2_000);
    v.propose(acct("x.testnet"), milli(1), None, None);
}

#[test]
fn over_cap_proposal_is_refused_and_leashes_the_agent() {
    let mut v = setup();
    as_agent(1, 2_000);
    let out = v.propose(acct("x.testnet"), near(1), None, None);
    assert_eq!(out.status, ProposalStatus::Refused);
    assert!(out.reason.unwrap().starts_with("over per-payment cap"));
    assert!(leashed(&v, "keeper").is_some());
    assert!(leashed(&v, "buyer").is_none(), "other agents keep running");
    assert!(v.get_pending(None).is_empty());
}

#[test]
fn payees_only_policy() {
    let mut v = setup();
    as_owner();
    v.set_policy(
        "keeper".into(),
        Policy {
            payees_only: true,
            ..policy()
        },
    );
    as_agent(1, 2_000);
    assert_eq!(
        v.propose(vendor(), milli(1), None, None).status,
        ProposalStatus::Pending
    );
    as_agent(1, 3_000);
    let out = v.propose(acct("stranger.testnet"), milli(1), None, None);
    assert!(out.reason.unwrap().starts_with("not an approved payee"));
}

#[test]
fn rapid_proposals_look_like_a_loop() {
    let mut v = setup();
    for ms in [2_000, 3_000, 4_000] {
        as_agent(1, ms);
        assert_eq!(
            v.propose(acct("x.testnet"), milli(10), None, None).status,
            ProposalStatus::Pending
        );
    }
    as_agent(1, 5_000);
    assert!(v
        .propose(acct("x.testnet"), milli(10), None, None)
        .reason
        .unwrap()
        .starts_with("proposal loop"));
}

#[test]
fn daily_limit_counts_approved_payments() {
    let mut v = setup();
    let mut ms = 2_000;
    for _ in 0..4 {
        as_agent(1, ms);
        let id = v.propose(vendor(), milli(500), None, None).id;
        as_guard(ms + 500);
        assert_eq!(v.approve(id, None), ProposalStatus::Paid);
        ms += 70_000;
    }
    as_agent(1, ms);
    assert!(v
        .propose(vendor(), milli(1), None, None)
        .reason
        .unwrap()
        .starts_with("over daily limit"));
}

#[test]
fn approval_rechecks_the_invoice() {
    let mut v = setup();
    let inv = invoice(&mut v, milli(200));
    as_agent(1, 2_000);
    let wrong_amount = v.propose(vendor(), milli(300), Some(inv), None).id;
    as_agent(2, 2_100);
    let wrong_payee = v
        .propose(acct("inkwe11.testnet"), milli(200), Some(inv), None)
        .id;
    as_guard(3_000);
    assert_eq!(v.approve(wrong_amount, None), ProposalStatus::Expired);
    assert_eq!(v.approve(wrong_payee, None), ProposalStatus::Expired);
    assert!(v
        .get_proposal(wrong_payee)
        .unwrap()
        .reason
        .as_ref()
        .unwrap()
        .contains("does not match invoice"));
    assert_eq!(v.get_invoice(inv).unwrap().status, InvoiceStatus::Open);
}

#[test]
fn an_invoice_is_paid_once() {
    let mut v = setup();
    let inv = invoice(&mut v, milli(200));
    as_agent(1, 2_000);
    let a = v.propose(vendor(), milli(200), Some(inv), None).id;
    as_agent(1, 2_100);
    let b = v.propose(vendor(), milli(200), Some(inv), None).id;
    as_guard(3_000);
    assert_eq!(v.approve(a, None), ProposalStatus::Paid);
    assert_eq!(v.approve(b, None), ProposalStatus::Expired);
}

#[test]
fn stale_proposals_expire() {
    let mut v = setup();
    as_agent(1, 2_000);
    let id = v.propose(vendor(), milli(100), None, None).id;
    as_guard(2_000 + PROPOSAL_TTL_MS + 1);
    assert_eq!(v.approve(id, None), ProposalStatus::Expired);
}

#[test]
#[should_panic(expected = "only approved payees can raise invoices")]
fn strangers_cannot_raise_invoices() {
    let mut v = setup();
    ctx(acct("mallory.testnet"), key(9), 1_500);
    v.create_invoice(milli(100), "pay me".into());
}

#[test]
fn blocklisted_receiver_is_refused() {
    let mut v = setup();
    as_guard(1_500);
    v.block_receiver(acct("drainer.testnet"));
    as_agent(1, 2_000);
    assert!(v
        .propose(acct("drainer.testnet"), milli(1), None, None)
        .reason
        .unwrap()
        .starts_with("scam blocklist"));
}

#[test]
#[should_panic(expected = "agent is leashed")]
fn leashed_agent_cannot_propose() {
    let mut v = setup();
    as_guard(1_500);
    v.leash("keeper".into(), "prompt injection".into());
    as_agent(1, 2_000);
    v.propose(acct("x.testnet"), milli(1), None, None);
}

#[test]
#[should_panic(expected = "only the owner may do this")]
fn guard_cannot_release() {
    let mut v = setup();
    as_guard(1_500);
    v.leash("keeper".into(), "dangerous".into());
    v.release("keeper".into(), None);
}

#[test]
fn owner_releases_with_a_fresh_key() {
    let mut v = setup();
    as_guard(1_500);
    v.leash("keeper".into(), "key leaked".into());
    as_owner();
    v.release("keeper".into(), Some(key(7)));
    assert!(leashed(&v, "keeper").is_none());
    as_agent(7, 2_000);
    assert_eq!(
        v.propose(acct("x.testnet"), milli(1), None, None).status,
        ProposalStatus::Pending
    );
    assert_eq!(v.get_incidents().last().unwrap().kind, "released");
}

#[test]
#[should_panic(expected = "unknown agent key")]
fn old_key_is_dead_after_rotation() {
    let mut v = setup();
    as_guard(1_500);
    v.leash("keeper".into(), "key leaked".into());
    as_owner();
    v.release("keeper".into(), Some(key(7)));
    as_agent(1, 2_000);
    v.propose(acct("x.testnet"), milli(1), None, None);
}

#[test]
fn pages_are_newest_first() {
    let mut v = setup();
    for i in 0..5u64 {
        as_agent(1, 2_000 + i * 30_000);
        v.propose(acct("x.testnet"), milli(1), None, None);
    }
    let ids: Vec<u64> = v
        .get_proposals(None, Some(3))
        .iter()
        .map(|p| p.id)
        .collect();
    assert_eq!(ids, vec![4, 3, 2]);
    assert_eq!(v.get_config().proposals, 5);
}
