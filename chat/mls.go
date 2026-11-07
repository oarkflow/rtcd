package chat

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/rtcd/dbx"
)

// An MLS (RFC 9420) delivery service.
//
// The service is still a mailbox and never a participant: it holds no group
// secret, parses no MLS structure and cannot read a handshake. What it adds to
// the per-device epoch scheme in keys.go is what RFC 9420 §14 asks of a
// delivery service, and nothing more:
//
//   - a KeyPackage directory, with single-use packages and one reusable
//     "last resort" package per device, so a member can be added while they are
//     offline and the supply can never be drained to nothing;
//   - one total order of handshake messages per conversation, where a commit is
//     a compare-and-swap on the epoch (of N concurrent commits at one epoch,
//     exactly one is stored), and a commit and the welcomes that go with it are
//     one transaction;
//   - the latest GroupInfo, stored once, so a Welcome can stay a few hundred
//     bytes (the ratchet tree is fetched, not copied into every Welcome) and a
//     device that has lost its state can rejoin by external commit.
//
// A conversation's MLS epoch is rtc_conv.epoch, the same counter the older
// scheme uses, so application messages (msg.send), retention, lifetimes,
// deletes and read cursors work unchanged and a message is refused when the
// sender's epoch is not the group's. The membership fence is the existing
// rekey flag: when someone is taken out of the roster the flag is raised, and
// it falls only when a commit names every person who was removed. A removed
// member still holds the epoch's secrets, so until then no application message
// is carried (handshakes are, because they are the way out).
//
// What the service does not do, and a client must: check that a commit really
// removed the people it says it did (the roster is public, so any member can),
// check a KeyPackage's signature, lifetime and credential, and check a
// GroupInfo. A member who commits a lie cannot be caught by a server that
// cannot read the commit; every other member can catch it, and the client is
// where that check lives.

var (
	// ErrEpochConflict: another commit created the epoch first.
	ErrEpochConflict = errors.New("chat: another commit created that epoch")
)

// EpochConflict carries the epoch the group is now at.
type EpochConflict struct{ Current int64 }

func (e *EpochConflict) Error() string   { return fmt.Sprintf("current_epoch=%d", e.Current) }
func (e *EpochConflict) Is(t error) bool { return t == ErrEpochConflict }

// Limits on what a client may hand the service. They bound storage and fan-out;
// none of them is a statement about MLS.
const (
	MaxKeyPackage    = 8 << 10
	MaxKeyPackages   = 100 // stored per device, single-use ones
	MaxPutBatch      = 100
	MaxGroupID       = 128
	MaxCommit        = 256 << 10
	MaxWelcome       = 64 << 10
	MaxGroupInfo     = 1 << 20 // carries the ratchet tree, so it grows with the group
	MaxWelcomes      = 1000
	MaxHandshakeID   = 64
	MaxClaimUsers    = 200
	MaxSyncPage      = 200
	DefaultKPTTL     = 30 * 24 * time.Hour
	MaxKPTTL         = 90 * 24 * time.Hour
	handshakeInsertN = 100
)

// Handshake kinds, spelled as in the Aura delivery contract.
const (
	KindCommit   = "commit"
	KindProposal = "proposal"
	KindWelcome  = "welcome"
)

func (s *Store) openMLS(ctx context.Context) error {
	key := "VARCHAR(191)"
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS rtc_mls_kp (tenant ` + key + ` NOT NULL, user_id ` + key + ` NOT NULL, device ` + key + ` NOT NULL,
			ref ` + key + ` NOT NULL, kp TEXT NOT NULL, last_resort INTEGER NOT NULL DEFAULT 0, created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
			PRIMARY KEY (tenant, user_id, device, ref))`,
		`CREATE INDEX IF NOT EXISTS rtc_mls_kp_exp ON rtc_mls_kp (expires_at)`,
		`CREATE TABLE IF NOT EXISTS rtc_mls_group (tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL, group_id ` + key + ` NOT NULL,
			suite INTEGER NOT NULL, seq BIGINT NOT NULL DEFAULT 0, group_info TEXT NOT NULL DEFAULT '', gi_epoch BIGINT NOT NULL DEFAULT 0,
			created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL, PRIMARY KEY (tenant, conv))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS rtc_mls_group_id ON rtc_mls_group (tenant, group_id)`,
		`CREATE TABLE IF NOT EXISTS rtc_mls_hs (tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL, seq BIGINT NOT NULL, epoch BIGINT NOT NULL,
			kind VARCHAR(12) NOT NULL, mid ` + key + ` NOT NULL, sender ` + key + ` NOT NULL, sender_dev ` + key + ` NOT NULL, body TEXT NOT NULL,
			to_user ` + key + ` NOT NULL DEFAULT '', to_dev ` + key + ` NOT NULL DEFAULT '', created_at BIGINT NOT NULL,
			PRIMARY KEY (tenant, conv, seq))`,
		`CREATE INDEX IF NOT EXISTS rtc_mls_hs_age ON rtc_mls_hs (created_at)`,
		// People taken out of the roster whom no commit has yet removed.
		`CREATE TABLE IF NOT EXISTS rtc_mls_removed (tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL, user_id ` + key + ` NOT NULL,
			at BIGINT NOT NULL, PRIMARY KEY (tenant, conv, user_id))`,
	} {
		if err := dbx.DDL(ctx, s.db, s.o.Dialect, q); err != nil {
			return fmt.Errorf("chat: schema: %w", err)
		}
	}
	return dbx.AddColumn(ctx, s.db, "rtc_conv", "mls", "INTEGER NOT NULL DEFAULT 0")
}

// KPRef is the identifier of a KeyPackage: the hex SHA-256 of the bytes the
// client uploaded. The service computes it, so a client cannot choose one that
// collides with another device's.
func KPRef(kp string) string {
	h := sha256.Sum256([]byte(kp))
	return hex.EncodeToString(h[:])
}

func validB64(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return err == nil
}

// ---------------------------------------------------------------------------
// KeyPackages.
// ---------------------------------------------------------------------------

// KPIn is a KeyPackage to publish.
type KPIn struct {
	KP         string `json:"kp"`
	LastResort bool   `json:"last_resort,omitempty"`
	// TTL, in seconds, is how long the service keeps it (default 30 days, at
	// most 90). The package carries its own lifetime, which the claimer checks.
	TTL int64 `json:"ttl,omitempty"`
}

// PutKeyPackages stores a device's KeyPackages and reports how many were new.
// A device holds at most MaxKeyPackages single-use packages and one last-resort
// package; a new last-resort package replaces the old one.
func (s *Store) PutKeyPackages(ctx context.Context, tenant, user, device string, in []KPIn) (added int, err error) {
	if !ValidDeviceID(device) || len(in) == 0 || len(in) > MaxPutBatch {
		return 0, ErrInvalid
	}
	if d, derr := s.device(ctx, tenant, user, device); derr == nil && d.Revoked {
		return 0, ErrRevoked
	} else if derr != nil && !errors.Is(derr, ErrNotFound) {
		return 0, derr
	}
	now := s.o.Now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var have int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_mls_kp WHERE tenant=$1 AND user_id=$2 AND device=$3 AND last_resort=0 AND expires_at>$4`), tenant, user, device, now).Scan(&have); err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, k := range in {
		if !validB64(k.KP, MaxKeyPackage) || k.TTL < 0 {
			return 0, fmt.Errorf("%w: a key package is 1 to %d base64url characters", ErrInvalid, MaxKeyPackage)
		}
		ttl := time.Duration(k.TTL) * time.Second
		if ttl == 0 {
			ttl = DefaultKPTTL
		}
		if ttl > MaxKPTTL {
			ttl = MaxKPTTL
		}
		ref := KPRef(k.KP)
		if seen[ref] {
			continue
		}
		seen[ref] = true
		if k.LastResort {
			// One per device: the new one replaces the old.
			if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM rtc_mls_kp WHERE tenant=$1 AND user_id=$2 AND device=$3 AND last_resort=1`), tenant, user, device); err != nil {
				return 0, err
			}
		} else if have+added >= MaxKeyPackages {
			return added, fmt.Errorf("%w: at most %d key packages per device", ErrLimit, MaxKeyPackages)
		}
		lr := 0
		if k.LastResort {
			lr = 1
		}
		_, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_mls_kp (tenant, user_id, device, ref, kp, last_resort, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`),
			tenant, user, device, ref, k.KP, lr, now, now+ttl.Milliseconds())
		if err != nil {
			if dbx.IsDuplicate(err) {
				continue // the same package again
			}
			return 0, err
		}
		added++
	}
	return added, tx.Commit()
}

// KeyPackageCount reports how many single-use packages a device has left, and
// whether it has a last-resort one, so a client knows when to top up.
func (s *Store) KeyPackageCount(ctx context.Context, tenant, user, device string) (available int, lastResort bool, err error) {
	now := s.o.Now().UnixMilli()
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT last_resort, COUNT(*) FROM rtc_mls_kp WHERE tenant=$1 AND user_id=$2 AND device=$3 AND expires_at>$4 GROUP BY last_resort`), tenant, user, device, now)
	if err != nil {
		return 0, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var lr, n int
		if err := rows.Scan(&lr, &n); err != nil {
			return 0, false, err
		}
		if lr == 1 {
			lastResort = n > 0
		} else {
			available = n
		}
	}
	return available, lastResort, rows.Err()
}

// Claimed is a KeyPackage handed to someone who is adding a device.
type Claimed struct {
	User       string `json:"user"`
	Device     string `json:"device"`
	KP         string `json:"kp"`
	LastResort bool   `json:"last_resort,omitempty"`
}

// ClaimKeyPackages gives the caller one KeyPackage for every active device of
// each user, in one transaction. A single-use package is consumed; a device
// with none left yields its last-resort package, which stays. Users with
// nothing to give are returned in missing. It is one round trip however many
// people are being added, which is what makes adding a hundred members cheap.
func (s *Store) ClaimKeyPackages(ctx context.Context, tenant string, users []string) (out []Claimed, missing []string, err error) {
	if len(users) == 0 || len(users) > MaxClaimUsers {
		return nil, nil, ErrInvalid
	}
	now := s.o.Now().UnixMilli()
	for attempt := 0; attempt < 4; attempt++ {
		out, missing, err = s.claimOnce(ctx, tenant, users, now)
		if !errors.Is(err, errClaimRace) {
			return out, missing, err
		}
	}
	return nil, nil, fmt.Errorf("%w: key packages are being claimed faster than they can be handed out", ErrLimit)
}

var errClaimRace = errors.New("chat: claim raced")

func (s *Store) claimOnce(ctx context.Context, tenant string, users []string, now int64) ([]Claimed, []string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	q, args := inList(`SELECT user_id, device, ref, kp, last_resort FROM rtc_mls_kp WHERE tenant=$1 AND expires_at>$2 AND user_id IN (`, []any{tenant, now}, users)
	rows, err := tx.QueryContext(ctx, s.rebind(q+` ORDER BY user_id, device, last_resort, created_at`), args...)
	if err != nil {
		return nil, nil, err
	}
	type cand struct {
		ref, kp string
		lr      bool
	}
	devs := map[[2]string][]cand{}
	for rows.Next() {
		var u, d, ref, kp string
		var lr int
		if err := rows.Scan(&u, &d, &ref, &kp, &lr); err != nil {
			rows.Close()
			return nil, nil, err
		}
		devs[[2]string{u, d}] = append(devs[[2]string{u, d}], cand{ref, kp, lr == 1})
	}
	rows.Close()
	// A device that has been revoked gets nothing, even if packages are left.
	revoked := map[[2]string]bool{}
	if len(devs) > 0 {
		rq, rargs := inList(`SELECT user_id, device FROM rtc_devkeys WHERE tenant=$1 AND revoked=1 AND user_id IN (`, []any{tenant}, users)
		rr, err := tx.QueryContext(ctx, s.rebind(rq), rargs...)
		if err != nil {
			return nil, nil, err
		}
		for rr.Next() {
			var u, d string
			if err := rr.Scan(&u, &d); err != nil {
				rr.Close()
				return nil, nil, err
			}
			revoked[[2]string{u, d}] = true
		}
		rr.Close()
	}
	keys := make([][2]string, 0, len(devs))
	for k := range devs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	var out []Claimed
	got := map[string]bool{}
	for _, k := range keys {
		if revoked[k] {
			continue
		}
		c := devs[k][0] // single-use first (the query orders last_resort ascending)
		if !c.lr {
			r, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM rtc_mls_kp WHERE tenant=$1 AND user_id=$2 AND device=$3 AND ref=$4`), tenant, k[0], k[1], c.ref)
			if err != nil {
				return nil, nil, err
			}
			if n, _ := r.RowsAffected(); n == 0 {
				return nil, nil, errClaimRace // another claimer took it between our read and delete
			}
		}
		out = append(out, Claimed{User: k[0], Device: k[1], KP: c.kp, LastResort: c.lr})
		got[k[0]] = true
	}
	if err := tx.Commit(); err != nil {
		if dbx.IsRetryable(err) {
			return nil, nil, errClaimRace
		}
		return nil, nil, err
	}
	var missing []string
	for _, u := range users {
		if !got[u] {
			missing = append(missing, u)
		}
	}
	return out, missing, nil
}

// DropKeyPackages deletes a device's packages (when it is revoked) or, with an
// empty device, every package of a user.
func (s *Store) DropKeyPackages(ctx context.Context, tenant, user, device string) error {
	if device == "" {
		_, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_mls_kp WHERE tenant=$1 AND user_id=$2`), tenant, user)
		return err
	}
	_, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_mls_kp WHERE tenant=$1 AND user_id=$2 AND device=$3`), tenant, user, device)
	return err
}

// ---------------------------------------------------------------------------
// Groups.
// ---------------------------------------------------------------------------

// MLSGroup is the delivery service's view of a conversation's group.
type MLSGroup struct {
	Conv    string `json:"conv"`
	GroupID string `json:"group_id"`
	Suite   int    `json:"suite"`
	Epoch   int64  `json:"epoch"`
	// Seq is the number of the newest handshake message.
	Seq int64 `json:"seq"`
	// Rekey is set while someone has been taken out of the roster and no commit
	// has removed them; application messages are refused until one does.
	Rekey bool `json:"rekey_required"`
	// Pending are the people that commit has to remove.
	Pending []string `json:"pending_removals,omitempty"`
	// GroupInfo is the newest one, at GroupInfoEpoch.
	GroupInfo      string `json:"group_info,omitempty"`
	GroupInfoEpoch int64  `json:"group_info_epoch,omitempty"`
}

// ValidSuite reports whether the service allows a cipher suite.
func (s *Store) ValidSuite(suite int) bool {
	allowed := s.o.MLSSuites
	if len(allowed) == 0 {
		allowed = DefaultMLSSuites
	}
	for _, a := range allowed {
		if a == suite {
			return true
		}
	}
	return false
}

// DefaultMLSSuites are the three RFC 9420 suites the service will carry
// without configuration. The service never inspects a suite's meaning: it
// records the one a group was created with and carries it back, so a client
// can refuse to join a group whose suite it considers too weak. Configure
// Options.MLSSuites to add a post-quantum suite, or to forbid the others.
var DefaultMLSSuites = []int{0x0001, 0x0002, 0x0003}

// CreateMLSGroup binds a conversation to an MLS group. The conversation must
// not already use the older epoch scheme, and may be bound only once; the
// group starts at epoch 0, which is the creator alone.
func (s *Store) CreateMLSGroup(ctx context.Context, tenant, conv, groupID string, suite int, groupInfo string) (MLSGroup, error) {
	if !validB64(groupID, MaxGroupID) || !s.ValidSuite(suite) || (groupInfo != "" && !validB64(groupInfo, MaxGroupInfo)) {
		return MLSGroup{}, ErrInvalid
	}
	if err := s.ensureConv(ctx, tenant, conv); err != nil {
		return MLSGroup{}, err
	}
	now := s.o.Now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return MLSGroup{}, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, s.rebind(`UPDATE rtc_conv SET mls=1, updated_at=$1 WHERE tenant=$2 AND conv=$3 AND epoch=0 AND mls=0`), now, tenant, conv)
	if err != nil {
		return MLSGroup{}, err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return MLSGroup{}, fmt.Errorf("%w: this conversation already has keys (an MLS group, or per-device epochs)", ErrConflict)
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO rtc_mls_group (tenant, conv, group_id, suite, group_info, gi_epoch, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`),
		tenant, conv, groupID, suite, groupInfo, int64(0), now); err != nil {
		if dbx.IsDuplicate(err) {
			return MLSGroup{}, fmt.Errorf("%w: that group id is already in use", ErrConflict)
		}
		return MLSGroup{}, err
	}
	if err := tx.Commit(); err != nil {
		return MLSGroup{}, err
	}
	s.dropState(tenant, conv)
	return MLSGroup{Conv: conv, GroupID: groupID, Suite: suite, GroupInfo: groupInfo}, nil
}

// MLSGroup returns a conversation's group, or ErrNotFound if it has none.
func (s *Store) MLSGroup(ctx context.Context, tenant, conv string) (MLSGroup, error) {
	g := MLSGroup{Conv: conv}
	var rekey int
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT g.group_id, g.suite, g.seq, g.group_info, g.gi_epoch, c.epoch, c.rekey
		FROM rtc_mls_group g JOIN rtc_conv c ON c.tenant=g.tenant AND c.conv=g.conv WHERE g.tenant=$1 AND g.conv=$2`), tenant, conv).
		Scan(&g.GroupID, &g.Suite, &g.Seq, &g.GroupInfo, &g.GroupInfoEpoch, &g.Epoch, &rekey)
	if errors.Is(err, sql.ErrNoRows) {
		return MLSGroup{}, ErrNotFound
	}
	if err != nil {
		return MLSGroup{}, err
	}
	g.Rekey = rekey != 0
	if g.Rekey {
		rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT user_id FROM rtc_mls_removed WHERE tenant=$1 AND conv=$2 ORDER BY user_id`), tenant, conv)
		if err != nil {
			return g, err
		}
		defer rows.Close()
		for rows.Next() {
			var u string
			if err := rows.Scan(&u); err != nil {
				return g, err
			}
			g.Pending = append(g.Pending, u)
		}
		return g, rows.Err()
	}
	return g, nil
}

// PutGroupInfo replaces the stored GroupInfo, which must be for the group's
// current epoch. It is how a member refreshes it without making a commit.
func (s *Store) PutGroupInfo(ctx context.Context, tenant, conv string, epoch int64, groupInfo string) error {
	if !validB64(groupInfo, MaxGroupInfo) {
		return ErrInvalid
	}
	r, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_mls_group SET group_info=$1, gi_epoch=$2, updated_at=$3
		WHERE tenant=$4 AND conv=$5 AND EXISTS (SELECT 1 FROM rtc_conv c WHERE c.tenant=$6 AND c.conv=$7 AND c.epoch=$8)`),
		groupInfo, epoch, s.o.Now().UnixMilli(), tenant, conv, tenant, conv, epoch)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		g, gerr := s.MLSGroup(ctx, tenant, conv)
		if gerr != nil {
			return gerr
		}
		return &EpochConflict{Current: g.Epoch}
	}
	return nil
}

// RemovedFromRoster notes that people left or were removed from a conversation
// that has an MLS group: they stay in the group until a commit removes them, so
// the conversation is fenced (rekey) until then. Their welcomes and key
// packages are dropped at once. It reports whether the conversation is an MLS
// one.
func (s *Store) RemovedFromRoster(ctx context.Context, tenant, conv string, users []string) (bool, error) {
	var mls int
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT mls FROM rtc_conv WHERE tenant=$1 AND conv=$2`), tenant, conv).Scan(&mls)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && mls == 0) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	now := s.o.Now().UnixMilli()
	for _, u := range users {
		_, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_mls_removed (tenant, conv, user_id, at) VALUES ($1,$2,$3,$4)`), tenant, conv, u, now)
		if err != nil && !dbx.IsDuplicate(err) {
			return true, err
		}
		if _, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_mls_hs WHERE tenant=$1 AND conv=$2 AND kind=$3 AND to_user=$4`), tenant, conv, KindWelcome, u); err != nil {
			return true, err
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Handshake messages.
// ---------------------------------------------------------------------------

// Welcome is a Welcome for one device.
type Welcome struct {
	User   string `json:"user"`
	Device string `json:"device"`
	W      string `json:"w"`
}

// CommitIn is a commit and what goes with it.
type CommitIn struct {
	Tenant, Conv, By, ByDevice string
	// Epoch is the epoch the commit creates: the group's current epoch plus one.
	Epoch int64
	// ID is the sender's id for the commit. A retry after a lost answer carries
	// the same one, and finds its own commit already stored instead of losing
	// a race to itself.
	ID       string
	Body     string
	Welcomes []Welcome
	// GroupInfo, if set, becomes the stored GroupInfo for the new epoch.
	GroupInfo string
	// Removed are the people this commit removes from the group.
	Removed []string
}

// CommitOut says what a commit did.
type CommitOut struct {
	Epoch int64 `json:"epoch"`
	// Seq is the commit's number; its welcomes follow, one number each.
	Seq       int64 `json:"seq"`
	Duplicate bool  `json:"duplicate,omitempty"`
	// Rekey is still set if people were removed from the roster whom this commit did not remove.
	Rekey bool `json:"rekey_required,omitempty"`
	// Welcomed are the people who got a welcome, for the caller to notify.
	Welcomed []string `json:"-"`
}

// Commit stores a commit and its welcomes and moves the group to the next
// epoch, in one transaction. It fails with *EpochConflict if the epoch was
// already created. members is the roster; a welcome can go only to a member.
func (s *Store) Commit(ctx context.Context, in CommitIn, members []string) (CommitOut, error) {
	if in.Epoch < 1 || in.ID == "" || len(in.ID) > MaxHandshakeID || !validB64(in.Body, MaxCommit) || len(in.Welcomes) > MaxWelcomes ||
		(in.GroupInfo != "" && !validB64(in.GroupInfo, MaxGroupInfo)) || !ValidDeviceID(in.ByDevice) {
		return CommitOut{}, ErrInvalid
	}
	if d, err := s.device(ctx, in.Tenant, in.By, in.ByDevice); err == nil && d.Revoked {
		return CommitOut{}, ErrRevoked
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return CommitOut{}, err
	}
	isMember := make(map[string]bool, len(members))
	for _, m := range members {
		isMember[m] = true
	}
	seenW := map[[2]string]bool{}
	total := 0
	for _, w := range in.Welcomes {
		k := [2]string{w.User, w.Device}
		if !isMember[w.User] || !ValidDeviceID(w.Device) || !validB64(w.W, MaxWelcome) {
			return CommitOut{}, fmt.Errorf("%w: a welcome is for a device of a current member, 1 to %d characters", ErrInvalid, MaxWelcome)
		}
		if seenW[k] {
			return CommitOut{}, fmt.Errorf("%w: %s/%s has two welcomes", ErrInvalid, w.User, w.Device)
		}
		seenW[k] = true
		total += len(w.W)
	}
	if total > 8<<20 {
		return CommitOut{}, ErrInvalid
	}
	for _, u := range in.Removed {
		if isMember[u] {
			return CommitOut{}, fmt.Errorf("%w: %s is still in the conversation, so a commit cannot remove them", ErrInvalid, u)
		}
	}

	now := s.o.Now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return CommitOut{}, err
	}
	defer tx.Rollback()

	// Who this commit removes is cleared first, so the epoch statement below
	// decides whether the fence stays up with the answer in front of it.
	for _, u := range in.Removed {
		if _, err := tx.ExecContext(ctx, s.rebind(`DELETE FROM rtc_mls_removed WHERE tenant=$1 AND conv=$2 AND user_id=$3`), in.Tenant, in.Conv, u); err != nil {
			return CommitOut{}, err
		}
	}
	// The compare-and-swap. Of N commits to one epoch exactly one matches
	// `epoch = next-1`; the rest update nothing.
	r, err := tx.ExecContext(ctx, s.rebind(`UPDATE rtc_conv SET epoch=$1, updated_at=$2,
		rekey = CASE WHEN EXISTS (SELECT 1 FROM rtc_mls_removed x WHERE x.tenant=$3 AND x.conv=$4) THEN 1 ELSE 0 END
		WHERE tenant=$5 AND conv=$6 AND mls=1 AND epoch=$7`), in.Epoch, now, in.Tenant, in.Conv, in.Tenant, in.Conv, in.Epoch-1)
	if err != nil {
		return CommitOut{}, err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return s.commitLost(ctx, in)
	}
	k := int64(1 + len(in.Welcomes))
	if in.GroupInfo != "" {
		_, err = tx.ExecContext(ctx, s.rebind(`UPDATE rtc_mls_group SET seq=seq+$1, group_info=$2, gi_epoch=$3, updated_at=$4 WHERE tenant=$5 AND conv=$6`), k, in.GroupInfo, in.Epoch, now, in.Tenant, in.Conv)
	} else {
		_, err = tx.ExecContext(ctx, s.rebind(`UPDATE rtc_mls_group SET seq=seq+$1, updated_at=$2 WHERE tenant=$3 AND conv=$4`), k, now, in.Tenant, in.Conv)
	}
	if err != nil {
		return CommitOut{}, err
	}
	var last int64
	var rekey int
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT g.seq, c.rekey FROM rtc_mls_group g JOIN rtc_conv c ON c.tenant=g.tenant AND c.conv=g.conv WHERE g.tenant=$1 AND g.conv=$2`), in.Tenant, in.Conv).Scan(&last, &rekey); err != nil {
		return CommitOut{}, err
	}
	first := last - k + 1
	rows := make([]hsRow, 0, k)
	rows = append(rows, hsRow{seq: first, kind: KindCommit, mid: in.ID, body: in.Body})
	out := CommitOut{Epoch: in.Epoch, Seq: first, Rekey: rekey != 0}
	for i, w := range in.Welcomes {
		rows = append(rows, hsRow{seq: first + 1 + int64(i), kind: KindWelcome, mid: in.ID, body: w.W, toUser: w.User, toDev: w.Device})
		out.Welcomed = append(out.Welcomed, w.User)
	}
	if err := s.insertHS(ctx, tx, in.Tenant, in.Conv, in.Epoch, in.By, in.ByDevice, now, rows); err != nil {
		return CommitOut{}, err
	}
	if err := tx.Commit(); err != nil {
		return CommitOut{}, err
	}
	s.dropState(in.Tenant, in.Conv)
	return out, nil
}

// commitLost works out why the compare-and-swap matched nothing: the
// conversation has no MLS group, the epoch was taken by someone else, or the
// epoch was taken by this very commit on an earlier try.
func (s *Store) commitLost(ctx context.Context, in CommitIn) (CommitOut, error) {
	g, err := s.MLSGroup(ctx, in.Tenant, in.Conv)
	if err != nil {
		return CommitOut{}, err
	}
	var seq int64
	err = s.db.QueryRowContext(ctx, s.rebind(`SELECT seq FROM rtc_mls_hs WHERE tenant=$1 AND conv=$2 AND epoch=$3 AND kind=$4 AND sender=$5 AND sender_dev=$6 AND mid=$7`),
		in.Tenant, in.Conv, in.Epoch, KindCommit, in.By, in.ByDevice, in.ID).Scan(&seq)
	if err == nil {
		return CommitOut{Epoch: in.Epoch, Seq: seq, Duplicate: true, Rekey: g.Rekey}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return CommitOut{}, err
	}
	return CommitOut{}, &EpochConflict{Current: g.Epoch}
}

type hsRow struct {
	seq             int64
	kind, mid, body string
	toUser, toDev   string
}

func (s *Store) insertHS(ctx context.Context, tx *sql.Tx, tenant, conv string, epoch int64, by, byDev string, at int64, rows []hsRow) error {
	for i := 0; i < len(rows); i += handshakeInsertN {
		part := rows[i:min(i+handshakeInsertN, len(rows))]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO rtc_mls_hs (tenant, conv, seq, epoch, kind, mid, sender, sender_dev, body, to_user, to_dev, created_at) VALUES `)
		args := make([]any, 0, len(part)*12)
		for j, r := range part {
			if j > 0 {
				sb.WriteByte(',')
			}
			b := len(args)
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8, b+9, b+10, b+11, b+12)
			args = append(args, tenant, conv, r.seq, epoch, r.kind, r.mid, by, byDev, r.body, r.toUser, r.toDev, at)
		}
		if _, err := tx.ExecContext(ctx, s.rebind(sb.String()), args...); err != nil {
			return err
		}
	}
	return nil
}

// Propose stores a proposal at the group's current epoch. It does not move the
// epoch. The first proposal with a given id wins; a retry returns its number.
func (s *Store) Propose(ctx context.Context, tenant, conv, by, byDevice, id string, epoch int64, body string) (int64, error) {
	if id == "" || len(id) > MaxHandshakeID || !validB64(body, MaxCommit) || !ValidDeviceID(byDevice) {
		return 0, ErrInvalid
	}
	now := s.o.Now().UnixMilli()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var cur int64
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT epoch FROM rtc_conv WHERE tenant=$1 AND conv=$2 AND mls=1`), tenant, conv).Scan(&cur); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if epoch != cur {
		return 0, &EpochConflict{Current: cur}
	}
	var dup int64
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT seq FROM rtc_mls_hs WHERE tenant=$1 AND conv=$2 AND kind=$3 AND sender=$4 AND sender_dev=$5 AND mid=$6`),
		tenant, conv, KindProposal, by, byDevice, id).Scan(&dup); err == nil {
		return dup, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE rtc_mls_group SET seq=seq+1, updated_at=$1 WHERE tenant=$2 AND conv=$3`), now, tenant, conv); err != nil {
		return 0, err
	}
	var seq int64
	if err := tx.QueryRowContext(ctx, s.rebind(`SELECT seq FROM rtc_mls_group WHERE tenant=$1 AND conv=$2`), tenant, conv).Scan(&seq); err != nil {
		return 0, err
	}
	if err := s.insertHS(ctx, tx, tenant, conv, epoch, by, byDevice, now, []hsRow{{seq: seq, kind: KindProposal, mid: id, body: body}}); err != nil {
		return 0, err
	}
	return seq, tx.Commit()
}

// Handshake is one stored handshake message as a device reads it.
type Handshake struct {
	Seq     int64     `json:"seq"`
	Epoch   int64     `json:"epoch"`
	Kind    string    `json:"kind"`
	ID      string    `json:"id"`
	Sender  string    `json:"sender"`
	Device  string    `json:"sender_device"`
	Body    string    `json:"body"`
	Sent    time.Time `json:"sent_at"`
	Welcome bool      `json:"-"`
}

// Sync returns the handshake messages after `after`, oldest first, in the one
// order every member applies them. A welcome is returned only to the device it
// was made for. more is true when the page was full.
func (s *Store) Sync(ctx context.Context, tenant, conv, user, device string, after int64, limit int) (out []Handshake, more bool, err error) {
	if limit <= 0 || limit > MaxSyncPage {
		limit = MaxSyncPage
	}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT seq, epoch, kind, mid, sender, sender_dev, body, created_at FROM rtc_mls_hs
		WHERE tenant=$1 AND conv=$2 AND seq>$3 AND (kind<>$4 OR (to_user=$5 AND to_dev=$6)) ORDER BY seq ASC LIMIT `+fmt.Sprint(limit+1)),
		tenant, conv, after, KindWelcome, user, device)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var h Handshake
		var at int64
		if err := rows.Scan(&h.Seq, &h.Epoch, &h.Kind, &h.ID, &h.Sender, &h.Device, &h.Body, &at); err != nil {
			return nil, false, err
		}
		h.Sent = time.UnixMilli(at).UTC()
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		out, more = out[:limit], true
	}
	return out, more, nil
}

// PruneMLS removes handshake messages older than keep (they are only needed by
// a member that has been offline that long, who rejoins by external commit),
// expired key packages, and removal marks of conversations that no longer
// exist. The newest keepMin messages of a conversation are always kept.
func (s *Store) PruneMLS(ctx context.Context, keep time.Duration, keepMin int64) (int64, error) {
	now := s.o.Now()
	var total int64
	run := func(q string, args ...any) error {
		r, err := s.db.ExecContext(ctx, s.rebind(q), args...)
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		total += n
		return nil
	}
	if err := run(`DELETE FROM rtc_mls_kp WHERE expires_at<$1`, now.UnixMilli()); err != nil {
		return total, err
	}
	if keep > 0 {
		err := run(`DELETE FROM rtc_mls_hs WHERE created_at<$1 AND seq <= (SELECT g.seq FROM rtc_mls_group g WHERE g.tenant=rtc_mls_hs.tenant AND g.conv=rtc_mls_hs.conv) - $2`,
			now.Add(-keep).UnixMilli(), keepMin)
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
