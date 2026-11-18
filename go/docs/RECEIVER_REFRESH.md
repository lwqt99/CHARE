# Receiver refresh binding and local commit

Version `chare-go-pbc-v0.6.2` keeps the cipher, record format and snapshot-v2
format unchanged. It corrects two receiver refresh behaviors.

The receiver first verifies the independently pinned authority's signature.
It then reconstructs the full snapshot from the actual typed state and requires
exact equality with the authenticated bytes. A valid signature on unrelated
bytes, an earlier selected version, or another state is insufficient. This
matches the existing public sender acquisition check. Freshness still depends
on the specified trusted current-snapshot selection; this is not a fork or
rollback detector when the entire state itself is rolled back consistently.

Next, all selected namespace deliveries are actually opened and decoded into
a temporary list. Only when every opening succeeds are the current receiver
mask references replaced. A failure preserves all old references. A successful
refresh does not modify separately retained old integers. This is a synchronous
local all-or-nothing return behavior, not concurrency control, crash recovery,
secure memory erasure or protection from process-memory exposure. Temporary
openings are actual state under any exposure model that observes them.

The prior implementation only checked the snapshot signature and committed
each mask immediately after its opening. Three regression cases fail against
that implementation: an authentic unrelated snapshot, an authentic old snapshot
after installing a new version, and a signed noncanonical second delivery that
left the first namespace partially refreshed. The final case uses an authorized
malicious payload to test failure handling; it is not a signature forgery or
an attack within the honest-issuance confidentiality theorem.

## Cost and measurement

Every authenticated refresh now actually serializes and compares the complete
selected snapshot. If that snapshot has B bytes, each call adds O(B) local byte
processing and temporary storage. The explicit full-record representation can
have B=O(m N^2) source-element bytes before framing and authentication; N calls
can therefore add O(m N^3) cumulative local processing. This work is inside the
existing acquisition, catch-up and regrant measured intervals. It adds no wire
field, curve element or pairing, but it must not be treated as free merely
because the curve-operation counters are unchanged. It is not a network-time
measurement or a speedup.

Staging additionally uses m temporary scalar references and the actual decoded
scalar objects until commit. All source-DH opens and signature checks still
execute. Full snapshots, original records and projection arrays remain charged.

The run manifest identifies this profile as
`signed-state-binding-and-atomic-local-open-v1`. Result ingestion requires that
tag for v0.6.2 and retains earlier runs under their earlier scope. The tag is
provenance metadata, not a proof that arbitrary code executed correctly.

Functional tests establish the specified software behavior. Mathematical
security still rests on the conditional GBGM/ROM model, trusted snapshot and
issuer premises; no stronger theorem or new independent contribution follows.
