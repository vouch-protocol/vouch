# PAD-136: Kernel Enforcement Profile for Signed Agent Credentials

**Identifier:** PAD-136  
**Title:** How an Operating System Kernel Can Enforce What an Agent's Signed Credentials Allow: a Rule Set Anyone Can Recompute, One-Use Grants Tied to a Signed Request, Delegation That Can Only Narrow, and a Two-of-Three Breaker  
**Publication Date:** November 28, 2026  
**Prior Art Effective Date:** November 28, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** AI Safety / Agent Authorization / Operating System Enforcement / Delegation /
Verifiable Evidence
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-003 (Identity Sidecar Pattern), PAD-020 (Ratchet Lock Protocol), PAD-060 (Single-Use Audited Override), PAD-086 (Executable Caveats in Delegation Chains), PAD-104 (Per-Tool-Call Continuous-Trust Authorization)  

---

## 1. Abstract

An AI agent is a program. Its credentials say what it may do, and a checkpoint in front of
each tool checks them. But the agent is still an ordinary program on the machine. If it
goes around the checkpoint, the credential stops nothing.

There is one place a program cannot go around: the kernel. The kernel is the core of the
operating system. Every file a program opens, every connection it makes and every program
it starts passes through it.

I describe four methods that carry a signed credential down to the kernel, so that the
kernel enforces what the credential says. They share one design. They can be used together
or one at a time.

A picture helps. Think of an office building. The building's staff members hold every key.
They are the kernel. A contractor is let in to do a job. That is the agent. The front desk
checks the paperwork. That is a helper program I call the sidecar, which holds the signing
keys and checks credentials. An escort from the front office walks the contractor in and
hands the staff members the door list. That is the launcher, the program that starts the
agent.

1. **A door list anyone can recompute.** The list of doors the contractor may open is
   worked out from the signed work order by a fixed, published procedure. Anyone who holds
   the work order can work out the same list and compare its fingerprint with the one the
   building reports.
2. **A pass that works once.** Some doors stay locked. A door opens for one entry, for a
   short time. First the front desk signs a request for that entry in the contractor's
   name and checks it. A staff member cancels the pass as it is used.
3. **A subcontractor's badge never opens more doors than the contractor's.** When the
   contractor brings in a subcontractor, the staff members place the subcontractor under
   the contractor in their own records. Cancel the contractor, and from that moment every
   door refuses the contractor and everyone under the contractor. Then they are walked out.
4. **Two out of three, never all three.** An agent that has touched private data, has taken
   in content from an unknown source, and can send data out is dangerous. The staff members
   count which of these three the contractor has done. The first two pass. The third is
   refused, whichever one it is. I call this the breaker, after the switch in a fuse box
   that trips and cuts the power.

Key points:

- **The rules are worked out from the credential alone.** So a third party can recompute
  their fingerprint and see that the reported rules are exactly the credential's rules and
  no wider. How far to trust that they were applied depends on what stands behind the
  report: the operator's signature alone, or also a hardware chip. The report says which.
- **In its main form, the grant lives and dies in the kernel.** It carries the digest, a
  short fingerprint, of one signed request. It is used up in the same step that lets the
  operation through, and it expires on the kernel's own clock.
- **The chain of agents handing work to sub-agents and the kernel's own tree of process
  groups have the same shape.** Narrowing authority, and withdrawing it, follow the tree.
  One write makes every door in a branch refuse.
- **The breaker counts what the agent has done, in whatever order it does it.** It needs
  no judgment about content.

---

## 2. Problem Statement

### 2.1 A checkpoint the agent can walk around

Most agent permission checks sit in front of a tool call. The agent asks, the check runs,
the tool runs. But an agent that can run code can open a file or a connection directly. The
check never sees it.

### 2.2 "It was fenced" is a claim nobody else can check

The person or company that runs an agent, which I call the operator, can run it inside a
sandbox. A sandbox is a set of operating system rules that limit what a program can reach.
A party on the other side of a transaction has no way to know which rules were applied, or
whether they matched the agent's credential.

### 2.3 Standing permission is wider than any one action needs

A credential that allows reading customer files allows every customer file for as long as
it is valid. The agent needs one file, now. Nothing checks the single use, counts it, or
leaves a record of it.

### 2.4 A sub-agent's limits live only on paper

Delegation rules say a sub-agent gets no more authority than the agent that created it. On
the machine, the sub-agent is usually one more program with the same reach as its parent.

### 2.5 The dangerous combination forms while the agent runs

Whether an agent ends up holding private data, untrusted content and a way out depends on
what it does during a session. A check made when the credential was issued cannot see that.

---

## 3. Solution (The Invention)

### 3.1 Parts the four methods share

**People and programs.**

- The *operator* is the person or company that runs the agent.
- A *verifier* is anyone who checks a credential or a record, such as the service the
  agent is talking to.
- The *sidecar* is a helper program that holds the signing keys and signs for the agent,
  so the agent never holds a key (PAD-003).
- The *launcher* is the program that starts the agent.
- An *approver* is a person or service, named in the credential, whose signature is needed
  for certain operations.

**Terms.**

- A *credential* is a signed statement of what an agent may do.
- A *delegation chain* forms when one agent hands part of its authority to another. The
  second agent gets its own credential, signed by the first.
- A credential is *revoked* when it is withdrawn before its end date.
- A *process* is a running program.
- A *group* is the kernel's own way of collecting processes into a tree. A child process
  starts in its parent's group.
- A *system call* is a program's request to the kernel.
- A *hook* is a point inside the kernel where a small *checking program* runs before an
  operation proceeds and can refuse it.
- A *socket* is one end of a connection, to another machine or to another process on the
  same machine.
- An *object* is the thing an operation acts on: a file, a folder, a network address and
  port, or a program.
- A *place* is a file or folder named by a file pattern, together with everything under it.
- A *hard link* is a second name for the same file. A *symbolic link* is a small file that
  points to another path.
- A *handle* is an open reference a program holds to a file, folder, connection or
  process. It keeps pointing at the same thing even if names change.
- To *mount* is to attach a file system, or a copy of part of one, at a folder.
- A *kernel module* is code added to the kernel while it runs.
- *Kernel privileges* are the special rights, held by the administrator account by
  default, that let a program change how the kernel itself behaves.
- A *digest* is a short fixed-length fingerprint of some bytes, here SHA-256.
- *Canonical form* is one agreed way to write data as bytes, here the JSON
  Canonicalization Scheme (RFC 8785). Two parties writing the same data get the same bytes
  and the same digest.
- A *session* is one run of a root agent together with every sub-agent under it.
- A *kernel table* is a table of values kept in kernel memory that checking programs read
  and write.
- A *profile* is one published version of this design: the compiler's exact steps (below),
  the list of hooks, and the checking programs. Its name is the *profile identifier*.

**What is assumed.**

- The kernel does what it says.
- The launcher and the sidecar are the programs the operator installed. So are the
  supervisor and the proxy, where sections 3.3 and 5 use them.
- An approver is never an agent in the same tree.
- The operator does not run, outside the tree, anything the agent could have written.
- The agent is not assumed to be honest. Section 3.2 says what a verifier can conclude when
  the operator is not assumed to be honest either.

**Typed scope entries.** The credential's scope is a list of entries. Each entry has:

- a *kind*: file, network or program;
- a *pattern* naming what it covers, written against logical names such as `workspace`
  and never against one machine's paths;
- the *operations* allowed: read, write, create, delete, run, connect or listen;
- a *tier*: `open` (allowed outright) or `grantable` (allowed only with a one-use grant,
  section 3.3);
- a list of *labels* from `private`, `untrusted` and `outward` (section 3.5).

The scope also carries three settings for the session as a whole:

- the *forbidden combinations* of labels (section 3.5);
- the *approvers*: the people or services who may approve an operation;
- the *caps*: how many grants, or how much budget, an agent and everything under it may
  draw in one session.

A scope entry may also be marked as needing a *second signer*. Then every grant for it
needs an approver's signature as well as the agent's. The mark makes the entry's tier
`grantable`.

**Patterns are nested or separate.** A file pattern is one file, or one folder with
everything under it. A network pattern is one host and port. It may also be a domain with
its sub-domains and a port, which is enforced only through the proxy in section 3.3. A
program pattern is one program. Any two patterns of the same kind are either nested, one
inside the other, or completely separate. They never partly overlap.

**How rules combine.** A *rule* is what the compiler makes from scope entries. There is one
rule per kind and pattern. Several rules can cover the same object, for example a rule for
a folder and a rule for a sub-folder inside it. Then:

- The tier and the labels belong to the object, whatever the operation.
- The tier is the strictest tier of every rule that covers the object: `grantable` over
  `open`.
- The labels are the labels of every rule that covers the object.
- The object needs a second signer if any rule that covers it needs one.
- The operation must be listed by at least one rule that covers the object. Otherwise it
  is refused.
- If no rule covers the object at all, the operation is refused.

Three rules cover moving things.

- Moving a file, or giving it a hard link, out of a place counts as reading it there. So it
  needs the read operation at the old place, at that place's tier and with its labels.
- Moving or deleting a folder is refused if any bound file or folder (section 3.2) lies
  anywhere beneath it. Otherwise a strict place could be carried away inside a looser one.
- Moving a file onto a name that already exists also deletes the file that was there. So
  it needs the delete operation at the new place. Swapping two names is checked as two
  moves.

**The compiler.** A fixed, published procedure turns the scope into a *rule set*:

1. It normalizes each pattern. Host names go to lower case. Repeated slashes in a path are
   removed. A pattern that contains `.` or `..` as a path part is rejected. Text uses one
   fixed encoding.
2. It writes `untrusted` and `outward` onto each network entry that has no label list. A
   network entry is a way to send data out and a source of content the operator does not
   control, unless the credential says otherwise. A label list that is written out and
   empty means no labels.
3. It merges entries that have the same kind and pattern into one rule. The rule has the
   operations of all of them, the labels of all of them, and the strictest of their tiers.
   An entry marked as needing a second signer counts as `grantable`.
4. It sorts each rule's operations and labels.
5. It sorts the rules by kind, then by the bytes of the pattern.
6. It adds the forbidden combinations, the approvers, the caps and the second-signer
   marks, each sorted.
7. It writes the result in canonical form.

The digest of those bytes is the *rule-set fingerprint*. Given the same scope and the same
profile identifier, everyone gets the same bytes.

**The launcher and the group.** The launcher prepares the agent's place in the kernel.

- It creates a new group for the agent. It adds the group to a *member table* in the
  kernel. Each row of that table names the group's parent and the root of its tree.
- It loads the rules into kernel tables keyed by the group.
- It starts the agent directly inside the group, or moves it there before the agent's own
  program begins. The rules are in place before the agent's first instruction runs.
- It starts the agent with no open files or connections beyond three standard streams: its
  input, its output and its error output.
- It detaches the agent from the terminal that started it.

**Separate accounts.** An *account* is an identity the operating system gives a program,
which decides what files it may touch. The agent runs under an account of its own. The
launcher, the sidecar, the supervisor and the proxy run under a different account. The
folders and files that control groups belong to that other account. This is required.
Linux lets a program start a child directly in another group if it holds a handle on
that group's folder and may write the group-control files of the groups involved. So a
file rule alone cannot keep the agent in its group. Ownership of those files can.

The launcher refuses a binding (section 3.2) that would cover any of these:

- the files that control groups;
- the files of the launcher, the sidecar, the supervisor or the proxy;
- the files an account runs when it logs in, and the files that schedule programs to run
  later.

**The agent has no way to change the rules.** Four things hold together.

- The agent never runs as the administrator account. It runs with no kernel privileges,
  and with the setting that stops a program from gaining any when it starts another
  program.
- From inside the tree, the checking programs refuse the system call that loads checking
  programs and opens kernel tables. They refuse loading kernel modules.
- From inside the tree, they refuse mounting, moving a mount, changing the root folder, and
  creating a user namespace. A *namespace* is a private view of the machine's files or
  network. A user namespace is the kind that would give an ordinary program the rights to
  make the others.
- The tables and checking programs are not kept anywhere the agent's account can open them.

So only the launcher and the sidecar can change the rules, the group rows and the grants.

**The agent cannot reach outside its tree.** From inside the tree to any process outside
it, the checking programs always refuse:

- sending a *signal*, which is a short message that can stop or end a process;
- *tracing*, which means watching or changing another process, and reading its memory;
- changing another process's resource limits or scheduling;
- connecting or sending to a local socket.

The first three are refused as well from any group to a process outside that group's own
branch. So a sub-agent cannot signal, trace or change the agent above it or beside it.

From inside the tree they also refuse, outright:

- creating a socket of a kind no rule can cover;
- the kernel's older shared memory, semaphores and message queues, which are kernel
  objects that outlive the processes that made them;
- the kernel's key store.

The one exception is a connection to the sidecar's socket. A connection to a service on
the same machine through a network address is a network operation like any other and
needs a rule.

**The group row and its lease.** Each group has a *group row* in a kernel table. It holds
two separate values: a status flag, live or revoked, and an expiry time on the kernel's own
clock.

- The sidecar keeps moving the expiry forward for as long as the credential is good. This
  is a lease. The expiry is never later than the credential's end date.
- Renewing the lease touches only the expiry. Nothing ever sets a revoked flag back to
  live.
- If the sidecar stops, or cannot confirm the credential, the lease runs out. From then on
  every operation by the group that reaches a hook is refused. The launcher, which watches
  the sidecar, then ends
  the tree's processes.
- The root agent's group has a lease like every other.

**What a hook does, in order.** Every hook follows the same steps.

1. It looks up the caller's group in the member table. A caller whose group is not there is
   not an agent, and the hook lets it through.
2. It follows the member table's rows from the caller's group up to the root of the tree.
   If it does not reach the root within the depth bound (section 3.4), it refuses.
3. It reads the group row at each level. If any is revoked or has lapsed, it refuses.
4. At each level it finds every rule that covers the object. Each level must have a rule
   there that lists the operation, or the hook refuses. The tier is the strictest tier
   found at any level. The labels are all the labels found at any level. An operation
   that touches two places, such as a move, takes the strictest tier and all the labels
   of both.
5. If the tier is `grantable`, it looks for a live grant without spending it. A *live*
   grant is one that is unspent and has not expired. If there is none, it refuses.
6. It makes the breaker decision (section 3.5). If the breaker would refuse, the hook
   looks for a live grant with an override mark (section 3.5) for the same key (the group,
   object and operations, section 3.3), whatever the tier. If
   there is none, it refuses, and any grant found in step 5 is left unspent.
7. If the operation will spend a grant, it reserves space for its report first. If it
   cannot, it refuses.
8. It spends the grant. If another caller got there first, it refuses.
9. It lets the operation through and sends the report.

A grant is spent only at step 8. So a report that a grant was spent always means the hook
let the operation through. A refusal at step 7 or 8 leaves the breaker's state as step 6
set it. That can only make the session stricter.

**Records.** The sidecar signs each record in this disclosure as a Verifiable Credential,
which is a standard format for a signed statement.

- The signature is attached as a Data Integrity proof, the standard way to sign such a
  statement. The suite is `eddsa-jcs-2022`. It applies Ed25519, a widely used signature
  method, to the canonical form.
- The sidecar signs records with an *enforcement key*. This key is separate from the key
  that signs on the agent's behalf. The agent cannot ask for anything to be signed with it.
- The enforcement key is listed under the operator's identity. A verifier trusts it the
  same way it trusts the operator's other keys.
- Every record other than an enforcement record carries the digest of the enforcement
  record (section 3.2) of the agent it concerns. This ties each record to one agent's run.
- The kernel's clock counts from when the machine started. So every kernel time in a record
  comes with an identifier for that start and with the ordinary date and time.

### 3.2 Method 1: a rule set anyone can recompute

**Step 1.** The launcher runs the compiler over the agent's credential. It gets the rule
set and its fingerprint.

**Step 2.** The launcher resolves each logical name to real objects on this machine. This
is the *binding table*.

- A file or folder is bound to the path as the launcher resolved it and to the *kernel
  identity* found at that path. The kernel identity is the set of numbers the kernel uses
  to tell that file or folder from others. The launcher keeps every bound file and folder
  open for the whole session, so its identity cannot pass to a different object.
- For each bound file or folder, the launcher also records the kernel identities of every
  folder above it. The hooks use this list to refuse moving or deleting those folders.
- A host name is bound to a list of addresses. The launcher looks the name up once, here.
  It writes the names and addresses into a hosts file, the local list a program checks
  before asking a name server. The launcher gives the agent its own view of that file
  before it starts, so the agent never needs to look a name up.
- A program is bound to a content digest that the kernel already holds for it.

The launcher refuses a binding table in which two patterns that are separate as names land
on the same object, or on objects nested one inside the other. Two host names bound to one
address are an example.

The launcher also refuses a binding table if a file beneath a `grantable` or labeled place
already has a second name, a hard link, anywhere. Hard links made during the session count
as reading at the old place (section 3.1).

The launcher resolves a pattern beneath a logical name from that name's open folder. It
refuses a link that leads out of it. It refuses a binding table in which the bound objects
are not nested exactly as the patterns are, in either direction. It also refuses one in
which any part of a `grantable` or labeled place is mounted a second time. So the rules on
the machine stay nested or separate, as the patterns are.

The binding table is written in canonical form and has its own digest.

**Step 3.** The launcher creates the group and loads the rules, as in section 3.1.

**Step 4.** The sidecar signs an *enforcement record*. It holds:

- the digest of the credential;
- the profile identifier;
- the rule-set fingerprint;
- the binding-table digest;
- the digests of the checking programs that were loaded;
- the kernel features actually in use;
- the group identifier;
- the kernel time at which the group was created, with the machine-start identifier and
  the ordinary date and time;
- the digest of the agent program to be started;
- the depth bound (section 3.4) and the local limit on a grant's life (section 3.3);
- the breaker's starting state, which state slot the tree uses, and whether it is shared
  (section 3.5);
- for a sub-agent, the parent's group and the digest of the parent's enforcement record;
- the assurance level, described below.

**Step 5.** The launcher starts the agent. The sidecar signs nothing on the agent's behalf
before the enforcement record exists.

**Step 6.** A verifier that holds the credential runs the same compiler and compares
fingerprints.

**Tying signatures to the session.** The sidecar takes the caller's group from the kernel,
never from the caller. It signs on the agent's behalf only for a caller whose own group is
the agent's group. Every signature it makes for the agent includes the digest of that agent's
enforcement record in what is signed. So a verifier that receives a signed message knows
which agent's run it came from, and can ask for that run's record.

**What the check proves.** I keep three things apart.

- *The rules.* A matching fingerprint shows the record states exactly the rules the
  credential implies, and no wider rule.
- *The bindings.* The operator gives the binding table to a verifier that asks. The digest
  in the record pins it. The verifier can then read, for example, that `workspace` was
  bound to one project folder and not to the whole disk.
- *That the rules were applied.* This rests on the record's *assurance level*.

There are two assurance levels.

- *Level one.* The record is the operator's signed statement, made with the enforcement
  key. It is attributable to the operator. The paths in the binding table, and the link
  between a signature and an agent's run, are the operator's statements too.
- *Level two.* A hardware trust chip also stands behind the record, as described next.

At level two, the machine uses a hardware trust chip.

- As the machine starts, each program records the digest of the next program in the chip
  before running it. The chip keeps these in a slot that only adds until the machine
  restarts, of a kind that cannot be reset while it runs.
- The digests of the kernel, the launcher, the sidecar and the checking programs go into a
  slot of their own, so later programs do not change it.
- The enforcement key is made inside the chip. The chip lets it sign only while that slot
  holds the expected digests.
- The chip signs, with its *attestation key*, a statement that the enforcement key was made
  inside it and is bound to those digests. The attestation key is a signing key the chip
  keeps for statements about itself.
- The record carries this statement, the list of digests, and a certificate for the
  attestation key. The certificate is either one the chip maker issued, or one issued
  after the chip proved that the attestation key sits beside the key the maker certified.
- The verifier checks all three. It compares the digests of the launcher, the sidecar and
  the checking programs with the ones the profile publishes. It compares the kernel's
  digest with a kernel it accepts.

This shows that the chip held these digests when the key signed the record. So the
expected kernel, launcher, sidecar and checking programs had started on that machine.

It does not show what happened to the tables afterward. That rests on the kernel, which
lets only the launcher and the sidecar change them. It also rests on the kernel keeping
the sidecar's memory, and so its use of the key, from every other program.

Without the chip's statement and the certificate, a record is at level one whatever it
says.

A verifier chooses the level it needs.

**Variations.**

- *Narrower than the credential.* An operator may apply a rule set that allows less than
  the credential implies. The record then carries the fingerprint of the full compiled set
  and the digest of the applied set. The operator gives the applied set to a verifier that
  asks. The verifier runs the containment check of section 3.4, with the applied set as the
  child and the compiled set as the parent.
- *Freshness.* The verifier sends a random value. The sidecar reads back from the kernel
  that the checking programs are still attached and the rules unchanged. It then signs a
  new record that includes the random value and the digest of the agent's first
  enforcement record. An old record cannot be replayed.
- *Other enforcement layers.* The same record format describes a rule set applied through
  any kernel mechanism. Fields that do not apply to a mechanism, such as the digests of
  checking programs, are left empty.

### 3.3 Method 2: a one-use grant tied to a signed request

Objects in the `grantable` tier are closed by default. One is opened like this.

**Step 1.** The agent asks the sidecar for one operation. It names the kind, the exact
target, the operations and a validity window. For a counted or budgeted grant it also
names the count or the budget. An operation that touches two places, such as a move,
names both places and every operation it needs at each.

**Step 2.** The sidecar writes the *request* from what the agent asked for. It takes the
agent's identity and group from the kernel-reported caller, never from the agent. It adds
a random value it chooses itself, used once, and the digest of the caller's own
enforcement record. It signs the request on that agent's behalf (PAD-003). The signed
request is the *request credential*. The *request digest* is the digest of the request
without any signature, so it stays the same however many signatures are attached.

**Step 3.** Where the object needs a second signer, the sidecar sends the request to an
approver. The approver signs over the same request bytes.

**Step 4.** The sidecar finds the object the kernel will see at the hook. It does this
without acting on anything the agent controls.

- For a file, it resolves the path beneath a bound folder's open handle. It does not follow
  links that lead out of that folder, and it does not open the file's contents.
- For a network target, it checks the name as written against the scope first. It then
  takes the addresses from the binding table. It never looks up a name for the agent.
- For a program, it takes the digest the kernel holds.
- For creating a file, the object is the parent folder's kernel identity and the new name.
  The same grant covers the first open of the file it creates. The hook for that open
  lets it through because the kernel marks a file it has just created.
- For moving a file or giving it a hard link, the object is the file's kernel identity,
  together with the new parent folder's kernel identity and the new name.

The sidecar keeps the object open until the grant is spent or lapses.

**Step 5.** The sidecar checks the request with fixed rules:

- every signature is valid;
- the agent's credential and its delegation chain are valid (PAD-104);
- nothing in the chain is revoked;
- the object is in the `grantable` tier and the operation is allowed for it;
- the window is current;
- this request digest has not been granted before;
- the caps are not exceeded. A cap belongs to an agent and counts its whole branch, so a
  grant to a sub-agent counts against its own cap and against the cap of every agent above
  it;
- where the object needs a second signer, an approver on the approver list has signed.

The sidecar keeps the request digests it has granted until their windows close. It keeps
them, and the cap counts, where a restart of the sidecar does not lose them.

**Step 6.** The sidecar writes a *grant* into the kernel table. One request makes one
grant, even when the operation needs several scope operations or touches two places. The
key is the group, the object (both objects for a move), and the operations. The value
holds:

- the request digest;
- an expiry time on the kernel's clock, the shorter of the request's window and a local
  limit;
- one fixed-size number, the *use word*.

The use word combines three things:

- a remaining-use count, one unless the request named more;
- a serial number no other grant has;
- whether the grant carries an override mark (section 3.5).

The value also holds a copy of the key itself and, separately from the use word, the
serial number. The kernel can reuse a removed value's memory for another key at once. These
copies let the hook tell whether the value it found still belongs to the key it looked up.

The sidecar never overwrites a grant the sweep has not yet removed. A second request for
such a key is refused.

**Step 7.** A process in the group reaches the hook, and the hook follows the order in
section 3.1.

- If the grant has expired, the hook refuses and leaves the grant for the sweep described
  below.
- It copies the stored key and the stored serial number. If the stored key is not the key
  it looked up, it refuses.
- It spends the grant in a single indivisible step. It replaces the whole use word with a
  spent value, but only if the word still holds the copied serial number and an unspent
  count. This is called a compare-and-swap.

Only the caller that wins that step proceeds. If two processes race, one gets through and
the other is refused.

**Step 8.** The checking program sends its report to the sidecar: the request digest, the
serial number, the group, the operation, the object and the kernel time. The space for the
report was reserved before the grant was spent. So a full report queue refuses the
operation and can never hide it. Each tree has its own report queue.

**Step 9.** The sidecar signs a *consumption record*. It takes the request digest from its
own list of grants, by the reported serial number. The record names that digest, so anyone
can find the request a use belongs to.

**The sweep.** The sidecar goes through the grant table on a timer.

- It removes spent grants.
- For a grant that expired unused, it first retires the use word by the same
  compare-and-swap the hook uses. Only if it wins does it remove the grant and sign a
  *lapse record*. So one grant never has both a lapse record and a consumption record.

**What a grant per use gives.**

- Each use is checked afresh against the chain and its revocation status.
- Each use is tied to one signed, attributable request.
- Each use counts against a cap.
- Each use can require a second signer.
- Each use leaves one record.

A grant opens one file or one connection. What then travels over that connection is
outside what the kernel sees.

Three further properties follow from the steps.

- The hook checks the object the kernel has already found. The sidecar found the object
  before it checked the scope. So swapping a path or a name after either check changes
  nothing.
- A grant is spent when the kernel lets the operation start, whether or not the operation
  later succeeds.
- If the sidecar stops, no new grants appear, the existing ones expire by themselves, and
  the group's lease runs out. From then on every operation that reaches a hook is
  refused.

**Variations.** I describe these for the record. Each uses the same parts as the main
form.

- *Grant sets.* A name bound to several addresses gets several keys that share one use
  word. The first connection to any of them spends it.
- *Counted and budgeted grants.* The count may be more than one. A grant may instead carry
  a budget, such as bytes sent, counted down at the hook for sending by the same
  compare-and-swap.
- *A forwarding proxy for names.* One address can serve many names, so a grant for an
  address reaches every name behind it. Where that matters, and for every pattern with
  sub-domains, the kernel rule lets the agent connect only to a local *forwarding proxy*.
  This is a program outside the agent's tree that passes connections on. The proxy keeps
  grants by destination name and spends one for each connection. It checks the name
  against the scope, and gets the breaker decision, before it looks the name up. A lookup
  is itself a way to send data out.
- *A supervisor instead of checking programs.* On a kernel without checking programs, a
  *system-call filter*, a small rule list the kernel checks on each system call, can pass
  the agent's calls to a supervisor process outside the tree. The supervisor applies the
  same order of checks and keeps the grants. It performs each allowed operation itself
  and hands the agent the resulting open file or connection. It never lets the agent's own
  call go ahead after checking it, because the agent could change the call's details
  after the check.

### 3.4 Method 3: delegation that can only narrow, on the kernel's group tree

**Placing the sub-agent.** Agent A asks the sidecar to start sub-agent B, and the sidecar
passes the request to the launcher. The launcher creates B's
group as a child of A's group and adds it to the member table. The delegation chain and the
kernel's group tree now have the same shape. The launcher starts B with no open files or
connections inherited from A, including any connection A holds to the sidecar.

**Containment check.** B's rule set is compiled from B's delegation credential. Before
loading it, the launcher compares it with A's rule set. This is the rule of delegation
chains that each hop can only narrow (PAD-020, PAD-086), checked here against the rules the
kernel will enforce.

It lists every pattern that appears in either rule set. For each pattern and each operation
it works out A's answer and B's answer, using the combining rules in section 3.1. An answer
is: allowed or refused, the tier, the labels, and whether a second signer is needed.
Patterns are nested or separate, and the binding table keeps the bound objects that way. So
checking each listed pattern covers every object.

For every pattern and operation that B allows, all of these must hold:

- A allows it too;
- B's tier there is at least as strict as A's;
- B's labels there include all of A's. A sub-agent can add a label and can never drop one;
- B needs a second signer there if A does.

Patterns and operations that B refuses need no check. Leaving something out is always
allowed. Three settings are checked as a whole:

- B's caps are no higher than A's.
- B's approvers are all approvers of A.
- B's forbidden combinations include all of A's.

If the check fails, the launcher refuses to start B.

**The kernel checks again on every operation.** This is the walk in section 3.1. Every
level must allow the operation. The strictest tier at any level wins, and the labels of
every level apply. A grant counts only if it names the caller's own group. So even a rule
set that was loaded wrongly cannot give a sub-agent more than its ancestors have. The
effective permission is always the overlap.

**Lifetime.** The expiry in B's group row is never later than the expiry in A's.

**Depth.** The launcher refuses to create a group deeper than a fixed bound. A hook that
does not reach the root of the agent's tree within the bound refuses. The bound is written
in the enforcement record, so a verifier can require one.

**Revocation of a branch.** When A's credential is revoked, three things happen in order.

1. The sidecar sets the status flag in A's group row with one write. Every hook reads the
   group row at every level. So every operation that reaches a hook after that write is
   refused, for A and for everything under A.
2. The sidecar ends or freezes every process in the branch and closes the branch's open
   connections. This stops the files and connections that were already open. The
   launcher removes a group's row from the member table only after the kernel reports the
   group empty. Otherwise a leftover process would stop counting as an agent.
3. The sidecar signs a *teardown record*. It holds the digest of the revoked credential,
   the group, the kernel time of the flag write, the kernel time at which the branch was
   confirmed stopped, and the numbers of processes ended and connections closed.

**Variations.**

- *Stopping open files and connections at the write.* The hooks for reading, writing,
  sending and receiving also read the group row at every level, both the flag and the
  lease. Then no read, write, send or receive call passes after the write, even on a file
  or connection opened earlier. A file already mapped into a process's memory keeps working
  until step 2 of the revocation ends the process.
- *Programs attached per group.* A checking program may instead be attached to each group,
  with the kernel running the programs of every level for each operation. The program at
  the root of the tree then makes the breaker decision and spends the grant, and only if
  no program below it refused.

### 3.5 Method 4: the two-of-three breaker

**Three classes.** Scope entries carry labels. `private` marks data that must not leak.
`untrusted` marks a source whose content the operator does not control. `outward` marks a
way to send data out. One entry may carry more than one label. Open web access is both
`untrusted` and `outward`.

**State.** The kernel keeps a small state value in a *state slot*. The value has three
bits, one per class. A table maps the root group of each delegation tree to its slot.
Normally a tree has a slot of its own. After the session starts, only checking programs
write the slot.

**Decision.** This is step 6 of the order in section 3.1. The labels are those found in
step 4. If there are none, the breaker does nothing. Otherwise:

1. The checking program reads the state.
2. It works out the state with these labels' bits added.
3. If that result has all three bits set, the breaker refuses. The state is left unchanged.
4. If not, and the result differs from the state, it reserves space to report the change.
   If it cannot, it refuses.
5. It stores the result, but only if the state has not changed since step 1.
6. If the state has changed, it starts again at step 1. It tries a bounded number of times
   and refuses if it cannot finish.

So any two classes are allowed in any order, and the operation that would complete the
third is refused, whichever class it is.

Bits are set whenever a labeled operation passes a hook: opening, creating, moving,
connecting and the rest. They are never cleared during the session. That is why a file or
connection opened earlier cannot be used to get around the breaker later.

**Scope of the state.** The state covers one session's tree, from its start to its end.
Carrying it from one session to the next is a variation below.

**Starting state.** The launcher also sets starting bits for the agent's three standard
streams. Input from an unknown party sets `untrusted`. An output or error stream that
reaches another party sets `outward`. A stream attached to a private store sets `private`.
A session with no such streams starts with all bits clear, unless a variation below
carries bits in.

**Trip record.** On a refusal the checking program reports the event. It also adds one to a
count kept in the kernel table, so a refusal is counted even if its report is lost. The
sidecar signs a *trip record*: the group, the class or classes refused, the operation, the
object, the state value and the kernel time. A trip can be reported to whoever issued the
credential.

**Variations.**

- *Override.* An approver named in the scope can let one refused operation through, in the
  spirit of the single-use override in PAD-060. The sidecar refuses while a standard
  stream reaches another party. It writes the current state into the request, and the
  approver signs it. The sidecar then sets every bit of the state, so every other labeled
  operation is refused, and closes the open network connections that share the state.
  Only then does it write a grant with an *override mark*. The hook lets an operation past
  the breaker only with a marked grant.
- *Carrying state between sessions.* Files an agent writes can outlive its session. The
  sidecar can save a session's `private` and `untrusted` bits against the places it may
  write, and start a later session that reads or writes those places with those bits set.
  Only those two bits are carried, because a file can hold private data or untrusted
  content but not a way out. Sessions that run at the same time over the same places can
  share one state slot.
- *Compartments.* A branch that the launcher keeps fully apart from the rest of the tree,
  with no shared writable places and no local channels across its edge, can have a state
  slot of its own. When it ends, its bits are added to its parent's state as a breaker
  decision, and its result is withheld if that decision refuses.
- *General form.* The same method works for any number of classes and any list of forbidden
  combinations, both taken from the scope. The state has one bit per class. An operation is
  refused when the bits it would add make the state include a forbidden combination. The
  hook uses the forbidden combinations of every level of the tree together. Two-of-three
  is the case of three classes and one forbidden combination.

### 3.6 How the four fit together

All four use one compiler, one group tree, one set of kernel tables and one record format.

The rule-set fingerprint covers the rules, their tiers and labels, the forbidden
combinations, the approvers, the caps and the second-signer marks. So a verifier that
recomputes the fingerprint from a credential knows which objects need a one-use grant,
which combinations the breaker refuses, and who may approve an operation.

The settings that belong to one agent's run are in its enforcement record: the depth bound,
the local limit on a grant's life, the breaker's starting state, and which state slot the
tree uses, and whether it is shared. A sub-agent's enforcement record names its parent's
group and the digest of its parent's record. So a verifier can follow the same chain in the
records that it follows in the credentials.

---

## 4. Prior Art Differentiation

A great deal here is prior art, and I do not claim it:

- kernel hooks that allow or refuse an operation, and sandboxes built on them;
- operating systems that build a sandbox from permissions signed into an application;
- collecting processes into a kernel tree with limits that pass down the tree;
- rule sets that can only tighten when stacked;
- compiling a policy written in a higher-level language into kernel checking programs;
- delegation chains whose authority can only shrink, and signed tokens to which each
  holder can add restrictions before passing them on;
- single-use and time-limited tokens, and permissions created for one action and removed
  after it;
- holding an operation in the kernel until a separate verifier signs a single-use verdict;
- giving a process an identity or a signature according to the group the kernel reports
  for it;
- operating systems that label a process after it reads secret data and then stop it from
  using the network, and label tracking in general;
- history-based access control, where what a subject has already touched decides what it
  may touch next;
- the "lethal trifecta" and "rule of two" descriptions of the three-way risk;
- proving to a remote party which software a machine is running, and recording the digest
  of a loaded kernel security policy as part of that proof.

What I describe as different is:

- **A rule set worked out from a signed credential by a fixed procedure.** Its fingerprint
  can be recomputed by anyone who holds the credential. The rule set is independent of the
  machine. A separate binding table ties it to one machine. The enforcement record carries
  both digests and the digests of the checking programs. The fingerprint also covers the
  forbidden combinations, the approvers and the caps.
- **A narrowing variant checked by containment.** The operator may apply less than the
  credential implies. The verifier runs the same containment check that is used for
  delegation.
- **Each signature made for the agent names the agent's enforcement record.** A signed
  message can be traced to the rules it was made under.
- **A kernel grant that carries the digest of a signed request.** It is spent in the same
  indivisible step that lets the operation through. It expires on the kernel's clock. The
  report's space is reserved before the grant is spent. Lapse records and consumption
  records complete it, and in a variant, grant sets.
- **Tier and labels that belong to the object, carried through delegation.** The strictest
  tier and all labels apply across nested rules and across every level of the tree. A grant
  counts only when it names the caller's own group.
- **Branch revocation by one status write, with a lease on every group row.** A signed
  teardown record states the kernel times of the write and of the confirmed stop.
- **A breaker whose class labels come from the credential's own scope through the same
  compiler.** The hook refuses whichever operation would complete the forbidden
  combination. In variants, an override completes the state first and then goes through a
  marked one-use grant from a request an approver has signed, and the state can be carried
  from one session to the next through the places an agent writes.
- **One fixed order of checks at every hook**, so that a spent grant always means the
  operation was let through.
- **The four working from one compiled rule set.**

---

## 5. Technical Implementation

The open implementation of Vouch Protocol includes a launcher, `vouch run`. It starts an
agent under a file-access rule set. The rules cannot be loosened once the agent starts. It
can also write a JSON record of the rules it applied. It uses Landlock, a Linux kernel
feature that an ordinary program can apply to itself.

The methods above extend that design. On Linux they map to existing kernel features as
follows.

- **Group.** A control group (cgroup, version 2). The group identifier is the cgroup
  identifier, which a checking program can read for the calling process.
- **A group with children.** When resource controls are turned on for a group's children,
  the group cannot hold processes of its own. Then A's own processes sit in an extra child
  group under A's group. That extra group's row in the member table names A's group as the
  group whose row and rules apply.
- **Checking programs.** eBPF programs. eBPF is the kernel's facility for loading small
  verified programs at chosen points.
- **Hooks.** eBPF programs attached to Linux Security Module hooks, the kernel's standard
  points for security decisions. The table below lists them.
- **Programs attached per group.** eBPF programs for security hooks or for connection
  attempts can be attached to a cgroup. In the kernel's *multi mode*, the programs of a
  group and of all its ancestors all run, even after one has refused. The operation
  proceeds only if every one allows it. A program can read the result the earlier ones
  left. The kernel allows this for connection hooks and for a limited number of security
  hooks.
- **Tables.** eBPF maps, kept separate: the member table; the rules per group; the status
  flag per group; the expiry per group; the grants, keyed by group, operation and object;
  the state slots; and the table from tree root to state slot.
- **Folder patterns.** A folder is bound to its kernel identity. At the hook the checking
  program walks from the file up through its parent folders to the top of the file system,
  crossing every mount point on the way. It collects every bound folder it passes. If it
  cannot reach the top within its step limit, the hook refuses.
- **Mounts on the walk.** Crossing mount points needs a hook that tells the checking
  program which mount the file was reached through. The kernel's path-based hooks do this
  for opening a file, starting a program, and for making, removing, renaming and linking
  files and folders, symbolic links, truncating, and changing mode and owner. The hooks for
  file times and extended attributes do not. So the launcher records every file system
  mounted beneath a bound folder. Where a hook carries no mount, the checking program
  refuses an operation on a file in one of those file systems.
- **Kernel identity.** The device number and the *inode number*, the number a file system
  gives each file. Some file systems can repeat that pair. There the identity also includes
  the sub-volume number, which tells apart separate trees inside one file system, or the
  generation number, which changes when an inode number is reused.
- **Indivisible steps.** An atomic compare-and-swap on a map value. A map can reuse a
  removed value's memory for another key at once. The copy of the key and the serial
  number in the use word catch that case.
- **Clock.** The kernel clock that counts from machine start and keeps counting while the
  machine sleeps, read inside the checking program. The machine-start identifier is the
  kernel's boot identifier.
- **Reports.** An eBPF *ring buffer*, a fixed-size queue from the kernel to a program, one
  per tree. Space is reserved before a grant is spent and released if the spend fails.
- **Decisions asked for from outside the kernel.** The proxy, the launcher and the sidecar
  ask for a breaker decision by running a checking program on request. eBPF lets a program
  outside the kernel run a checking program this way. So the state is still changed only
  inside the kernel, by compare-and-swap.
- **Caller's group.** The sidecar takes the caller's group from the kernel in one of two
  ways. It can ask for a process handle for the socket's peer, which stays tied to that one
  process. Or a checking program records the group when the socket is connected.
- **Stopping a branch.** The cgroup kill and freeze controls for the processes. The
  branch's sockets are destroyed from a *socket iterator*, a checking program the kernel
  runs once for each open socket.
- **Program digests.** A digest the kernel already holds. One source is fs-verity, a file
  system feature that computes and enforces a digest for a file. Another is the hash stored
  by the kernel's integrity subsystem.
- **Hardware trust chip.** On many machines a Trusted Platform Module. The chip can hold a
  key that works only while its recorded digests have stated values.

| Hook | Scope operation checked | Object |
|------|-------------------------|--------|
| Opening a file | read or write, by how it is opened | the file |
| Creating a file or folder | create | the parent folder and the new name |
| Deleting | delete | the file or folder |
| Renaming | read and delete at the old place, create at the new | the file, and the new folder and name |
| Renaming onto an existing name | as renaming, plus delete at the new place | the file, and the new folder and name |
| Linking | read at the old place, create at the new | the file, and the new folder and name |
| Truncating | write | the file |
| Changing a file's mode, owner, times or extended attributes | write | the file |
| Reading extended attributes | read | the file |
| Starting a program | run | the program |
| Connecting, or sending to a stated address | connect | the address and port |
| Binding, listening, accepting | listen | the address and port |
| Sending, for a byte budget | connect | the address and port |
| Reading, writing, sending, receiving (section 3.4 variation) | none, group row only | none |

*Extended attributes* are small named values a file system stores alongside a file. When a
program starts, the kernel also opens the program's file. That open is judged by the row
for starting a program.

The same layer supplies the refusals listed in section 3.1. The launcher refuses to start
if the kernel lacks a hook the profile needs.

**Without eBPF.** The supervisor variation in section 3.3 can use seccomp user
notification. This is the kernel's system-call filter, with an option to pass a call to a
supervisor process, which can answer it and pass back an open file or connection. Landlock
can serve as a fixed outer wall around the agent in that form.

Records are Verifiable Credentials with `eddsa-jcs-2022` Data Integrity proofs. The rule
set and the binding table are serialized with the JSON Canonicalization Scheme and hashed
with SHA-256.

The methods do not depend on Linux. They need a kernel hook on each governed operation, a
process grouping the agent cannot leave, kernel-held tables with an indivisible update, and
a kernel clock.

---

## 6. Claims Summary

Section 3 is the full disclosure, with every step and variation. This section restates its
main points, method by method, in the same words.

**Method 1**

1. I compile the scope of a signed credential into a kernel rule set by a fixed, published
   procedure. The rule set is written in canonical form. Its digest, the rule-set
   fingerprint, is reported in a signed enforcement record. Anyone holding the credential
   can recompute the fingerprint and compare.
2. The rule set uses logical names. A separate binding table maps them to paths and kernel
   identities on the machine. The record carries the digests of both, of the checking
   programs and of the agent program.
3. The launcher refuses a binding table in which patterns that are separate as names land
   on the same object or on nested objects.
4. The rule-set fingerprint also covers the forbidden combinations, the approvers, the caps
   and the second-signer marks.
5. The tier and the labels belong to the object, whatever the operation. The strictest tier
   and the labels of every covering rule apply. An object no rule covers is refused.
6. Moving a file out of a place counts as reading it there. Moving or deleting a folder
   with a bound object beneath it is refused.
7. In a variant, the operator may apply a rule set that allows less than the credential
   implies. The verifier checks it by the containment check used for delegation.
8. The record states its assurance level. Level one is the operator's signed statement. At
   level two, the enforcement key is made inside a hardware trust chip and can sign only
   while the chip holds the expected digests. The record carries the chip's statement, the
   list of digests and a certificate for the chip's attestation key.
9. In a variant, a verifier may send a random value. The sidecar re-reads the kernel state
   and signs a new record that includes the value and the digest of the agent's first
   record.
10. In a variant, the same record format describes a rule set applied through any kernel
    mechanism.
11. The sidecar signs for the agent only for a caller whose own group, as the kernel reports
    it, is the agent's group, and only once the enforcement record exists. Each such
    signature includes the digest of that record.

**Method 2**

12. A grant in a kernel table permits one operation on a `grantable` object. It carries the
    digest of a request signed for the agent. It is spent in the same indivisible kernel
    step that lets the operation proceed. It expires on the kernel's own clock.
13. The sidecar writes the request, including the random value and the agent's
    enforcement record digest. The request digest is taken over the request without any
    signature. An approver, where the object needs a second signer, signs over the same
    request bytes.
14. One request makes one grant, even for an operation that touches two places.
15. Before writing the grant, the sidecar finds the object without acting on anything the
    agent controls, and holds it open. It never looks up a name for the agent. It refuses a
    request digest it has granted before. It applies the caps up the whole chain.
16. The grant's use word combines a use count, a serial number and the override mark. The
    grant also holds a copy of its key and of the serial number. The spend replaces the
    whole word, and only if it still holds the copied serial number.
17. The sidecar never overwrites a grant the sweep has not yet removed.
18. Space for the report is reserved before the grant is spent. The operation is refused if
    it cannot be reserved.
19. A grant is spent when the kernel lets the operation start, whether or not the operation
    later succeeds. The spend is signed as a consumption record that names the request
    digest.
20. A sweep removes spent grants. It retires an expired unused grant by the same
    compare-and-swap, and signs a lapse record only if it wins.
21. In a variant, several keys may point at one shared use word, and the first use of any of
    them spends it. The count may be more than one, or a budget counted down at the hook for
    sending.
22. In a variant, a forwarding proxy keeps grants by destination name, and gets the
    breaker decision before any lookup. Patterns with sub-domains use this form.
23. In a variant, a supervisor outside the agent's tree receives the agent's system calls,
    applies the same order of checks, and performs each allowed operation itself.

**Method 3**

24. Each delegation in an agent's chain is placed as a child group in the kernel's group
    tree and added to the member table. The sub-agent starts with nothing open that it
    inherited from its parent.
25. Before a child's rule set is loaded, it is compared with the parent's. For everything
    the child allows, the parent allows it too, at a tier at least as strict, with at least
    the parent's labels and second signer. The child's caps, approvers and forbidden
    combinations are no looser.
26. Every operation is checked at every level up to the tree's root. The strictest tier and
    all labels apply. A grant counts only if it names the caller's own group.
27. The launcher refuses to create a group deeper than a bound. A hook that does not reach
    the root within the bound refuses. The bound is in the enforcement record.
28. Every group row has a status flag and, separately, a lease on the kernel clock that the
    sidecar keeps renewing. A child's expiry is never later than its parent's. When a lease
    runs out, every operation by the group that reaches a hook is refused.
29. Revoking a credential sets one status flag. Every operation that reaches a hook after
    that write is refused across the branch. The branch's processes and connections are
    then stopped. A signed teardown record states the kernel times of the write and of the
    confirmed stop.
30. In a variant, the hooks for reading, writing, sending and receiving also read the group
    row.
31. In a variant, a checking program is attached to each group, and the program at the
    root makes the breaker decision and spends the grant.

**Method 4**

32. Scope entries carry class labels. The kernel keeps a state value with one bit per
    class. An operation is refused when the bits it would add would complete a forbidden
    combination, in whatever order the classes are reached. Bits are never cleared during a
    session.
33. The classes are private data, untrusted input and outward communication, and the
    forbidden combination is all three. A network entry carries the last two unless it says
    otherwise.
34. The state covers one session's tree. In a variant, the `private` and `untrusted` bits
    are saved against the places a session may write and carried into later sessions over
    those places.
35. The launcher sets starting bits for the agent's three standard streams.
36. A refusal is counted in the kernel and signed as a trip record naming the classes, the
    operation and the object.
37. In a variant, an approver named in the scope lets one refused operation through. The
    sidecar first completes the state and closes the open network connections, then
    writes a grant with an override mark, the only kind the hook lets past the breaker.
38. In a variant, a branch kept fully apart from the rest of the tree has a state slot of
    its own, merged into its parent's state as a breaker decision when it ends.
39. In a variant, the same method serves any number of classes and any list of forbidden
    combinations taken from the scope.

**Together**

40. Every hook follows one fixed order of checks, with the grant spent last. A spent grant
    therefore always means the operation was let through. A caller whose group is not in
    the member table is not an agent and is let through.
41. The rules are in place before the agent's first instruction runs. The agent runs under
    its own account, cannot leave its group, and cannot change the tables. It cannot signal,
    trace or open a local channel to any process outside its tree, and no sub-agent can
    signal, trace or change a process outside its own branch. The one exception is a
    connection to the sidecar's socket.
42. Records are signed with an enforcement key that is separate from the agent's key, and
    the agent cannot ask for it to be used. Every record other than an enforcement record
    carries the digest of the enforcement record of the agent it concerns. Every kernel time
    comes with a machine-start identifier and the ordinary date and time.
43. The four methods are used together from one compiled rule set. A sub-agent's
    enforcement record names its parent's group and the digest of its parent's record.

---

## Prior Art Declaration

I publish this document as a defensive disclosure to establish prior art as of the date
above. The methods are released under Apache 2.0 and may be freely implemented. The aim is
to prevent patenting by any party, and to keep the methods available to the open
Vouch Protocol ecosystem and to the wider AI safety and operating system security
communities.
