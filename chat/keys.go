package chat

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/rtcd/dbx"
)

// Keys, epochs and the policy of a conversation.
//
// The service never holds a conversation key. It keeps three things that let
// the members hand one another keys without trusting it with them:
//
//   - a directory of device public keys (with an opaque certificate the
//     application can check against its own identity system, so the service
//     cannot substitute a key unnoticed);
//   - the conversation's current epoch, a counter that goes up each time the
//     members make a new key; and
//   - for each epoch, the key wrapped separately for every device that holds it.
//     A wrap is an opaque string the service stores and returns to that device.
//
// What the service does enforce is membership: a new epoch may only be wrapped
// for devices of current members, must cover every member, and is required
// (rekey_required) after anyone has left or a device has been revoked, so a
// removed person's key stops being the one messages are sealed under.

var (
	ErrStale    = errors.New("chat: stale epoch")
	ErrRekey    = errors.New("chat: a new epoch is required")
	ErrConflict = errors.New("chat: conflict")
	ErrRevoked  = errors.New("chat: device revoked")
)

// MissingKeys lists members a new epoch could not be wrapped for, because they
// have no device key published.
type MissingKeys struct{ Users []string }

func (e *MissingKeys) Error() string {
	return "chat: no device key for " + strings.Join(e.Users, ", ")
}

// State is a conversation's key epoch and policy.
type State struct {
	Epoch int64 `json:"epoch"`
	// Rekey is set when someone left or a device was revoked: messages are
	// refused until a member makes the next epoch.
	Rekey bool `json:"rekey_required"`
	// Retention removes a conversation's messages after this long (0: the
	// service's setting applies). TTL is the lifetime given to a message that
	// asks for none. DeleteWindow is how long a sender can delete for everyone.
	Retention    time.Duration `json:"retention,omitempty"`
	TTL          time.Duration `json:"default_ttl,omitempty"`
	DeleteWindow time.Duration `json:"delete_window,omitempty"`
}

type stateEntry struct {
	st State
	at time.Time
}

type stateCache struct {
	mu sync.Mutex
	m  map[string]stateEntry
}

const stateTTL = 2 * time.Second

func (s *Store) openKeys(ctx context.Context) error {
	key := "VARCHAR(191)"
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS rtc_conv (tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL, epoch BIGINT NOT NULL DEFAULT 0,
			rekey INTEGER NOT NULL DEFAULT 0, retention_s BIGINT NOT NULL DEFAULT 0, ttl_s BIGINT NOT NULL DEFAULT 0, window_s BIGINT NOT NULL DEFAULT 0,
			updated_at BIGINT NOT NULL, PRIMARY KEY (tenant, conv))`,
		`CREATE TABLE IF NOT EXISTS rtc_devkeys (tenant ` + key + ` NOT NULL, user_id ` + key + ` NOT NULL, device ` + key + ` NOT NULL,
			pub TEXT NOT NULL, cert TEXT NOT NULL, created_at BIGINT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (tenant, user_id, device))`,
		`CREATE TABLE IF NOT EXISTS rtc_epoch_keys (tenant ` + key + ` NOT NULL, conv ` + key + ` NOT NULL, epoch BIGINT NOT NULL,
			user_id ` + key + ` NOT NULL, device ` + key + ` NOT NULL, by_user ` + key + ` NOT NULL, by_device ` + key + ` NOT NULL,
			w TEXT NOT NULL, created_at BIGINT NOT NULL, PRIMARY KEY (tenant, conv, epoch, user_id, device))`,
		`CREATE INDEX IF NOT EXISTS rtc_epoch_keys_dev ON rtc_epoch_keys (tenant, user_id, device)`,
	} {
		if err := dbx.DDL(ctx, s.db, s.o.Dialect, q); err != nil {
			return fmt.Errorf("chat: schema: %w", err)
		}
	}
	s.states.m = map[string]stateEntry{}
	return nil
}

func (s *Store) ensureConv(ctx context.Context, tenant, conv string) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_conv (tenant, conv, updated_at) VALUES ($1,$2,$3)`), tenant, conv, s.o.Now().UnixMilli())
	if err != nil && !dbx.IsDuplicate(err) {
		return err
	}
	return nil
}

func (s *Store) dropState(tenant, conv string) {
	s.states.mu.Lock()
	delete(s.states.m, tenant+"\x00"+conv)
	s.states.mu.Unlock()
}

// State returns a conversation's epoch and policy. The answer may be up to two
// seconds old on this node (a change made through this node is seen at once).
func (s *Store) State(ctx context.Context, tenant, conv string) (State, error) {
	key := tenant + "\x00" + conv
	now := s.o.Now()
	s.states.mu.Lock()
	e, ok := s.states.m[key]
	s.states.mu.Unlock()
	if ok && now.Sub(e.at) < stateTTL {
		return e.st, nil
	}
	return s.stateFresh(ctx, tenant, conv)
}

func (s *Store) stateFresh(ctx context.Context, tenant, conv string) (State, error) {
	var st State
	var rekey int
	var ret, ttl, win int64
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT epoch, rekey, retention_s, ttl_s, window_s FROM rtc_conv WHERE tenant=$1 AND conv=$2`), tenant, conv).Scan(&st.Epoch, &rekey, &ret, &ttl, &win)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return State{}, err
	}
	st.Rekey = rekey != 0
	st.Retention, st.TTL, st.DeleteWindow = time.Duration(ret)*time.Second, time.Duration(ttl)*time.Second, time.Duration(win)*time.Second
	s.states.mu.Lock()
	if len(s.states.m) > 50000 {
		s.states.m = map[string]stateEntry{}
	}
	s.states.m[tenant+"\x00"+conv] = stateEntry{st, s.o.Now()}
	s.states.mu.Unlock()
	return st, nil
}

// Fresh is State without the cache, for when a refusal is about to be given.
func (s *Store) Fresh(ctx context.Context, tenant, conv string) (State, error) {
	return s.stateFresh(ctx, tenant, conv)
}

// Policy is a change to a conversation's policy; nil fields are left alone.
type Policy struct {
	Retention, TTL, DeleteWindow *time.Duration
}

// SetPolicy changes a conversation's retention, default message lifetime and
// delete window.
func (s *Store) SetPolicy(ctx context.Context, tenant, conv string, p Policy) error {
	if err := s.ensureConv(ctx, tenant, conv); err != nil {
		return err
	}
	set := func(col string, d *time.Duration) error {
		if d == nil {
			return nil
		}
		if *d < 0 || *d > MaxTTL*10 {
			return ErrInvalid
		}
		_, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_conv SET `+col+`=$1, updated_at=$2 WHERE tenant=$3 AND conv=$4`), int64(*d/time.Second), s.o.Now().UnixMilli(), tenant, conv)
		return err
	}
	for _, c := range []struct {
		col string
		d   *time.Duration
	}{{"retention_s", p.Retention}, {"ttl_s", p.TTL}, {"window_s", p.DeleteWindow}} {
		if err := set(c.col, c.d); err != nil {
			return err
		}
	}
	s.dropState(tenant, conv)
	return nil
}

// NeedRekey marks conversations that use epochs as needing a new one. It
// reports which were marked.
func (s *Store) NeedRekey(ctx context.Context, tenant string, convs []string) ([]string, error) {
	var out []string
	for _, c := range convs {
		r, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_conv SET rekey=1, updated_at=$1 WHERE tenant=$2 AND conv=$3 AND epoch>0 AND rekey=0`), s.o.Now().UnixMilli(), tenant, c)
		if err != nil {
			return out, err
		}
		if n, _ := r.RowsAffected(); n > 0 {
			out = append(out, c)
		}
		s.dropState(tenant, c)
	}
	return out, nil
}

// WithEpochs returns those of convs that have a key epoch.
func (s *Store) WithEpochs(ctx context.Context, tenant string, convs []string) ([]string, error) {
	var out []string
	for i := 0; i < len(convs); i += 200 {
		part := convs[i:min(i+200, len(convs))]
		q, args := inList(`SELECT conv FROM rtc_conv WHERE tenant=$1 AND epoch>0 AND conv IN (`, []any{tenant}, part)
		rows, err := s.db.QueryContext(ctx, s.rebind(q), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, c)
		}
		rows.Close()
	}
	return out, nil
}

// inList appends "$n,$n+1,…)" for vals to a query prefix.
func inList(prefix string, args []any, vals []string) (string, []any) {
	var sb strings.Builder
	sb.WriteString(prefix)
	for i, v := range vals {
		if i > 0 {
			sb.WriteByte(',')
		}
		args = append(args, v)
		fmt.Fprintf(&sb, "$%d", len(args))
	}
	sb.WriteByte(')')
	return sb.String(), args
}

// ---------------------------------------------------------------------------
// Device keys.
// ---------------------------------------------------------------------------

// Device is one device's public key.
type Device struct {
	User    string    `json:"user"`
	Device  string    `json:"device"`
	Pub     string    `json:"pub"`
	Cert    string    `json:"cert,omitempty"`
	Created time.Time `json:"created_at"`
	Revoked bool      `json:"revoked,omitempty"`
}

// Limits on what a device may publish.
const (
	MaxDeviceID = 64
	MaxPub      = 512
	MaxCert     = 8192
	MaxWrap     = 1024
)

// ValidDeviceID reports whether s may name a device.
func ValidDeviceID(s string) bool {
	if s == "" || len(s) > MaxDeviceID {
		return false
	}
	for _, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == ':'
		if !ok {
			return false
		}
	}
	return true
}

// PublishDevice records a device's public key. A device's key never changes: a
// different key under the same id is refused (use a new device id), and a
// revoked device stays revoked. Publishing the same key again only refreshes
// its certificate. maxDevices caps a user's active devices.
func (s *Store) PublishDevice(ctx context.Context, tenant, user, device, pub, cert string, maxDevices int) (Device, bool, error) {
	if !ValidDeviceID(device) || pub == "" || len(pub) > MaxPub || len(cert) > MaxCert {
		return Device{}, false, ErrInvalid
	}
	get := func() (Device, error) { return s.device(ctx, tenant, user, device) }
	if d, err := get(); err == nil {
		switch {
		case d.Revoked:
			return Device{}, false, ErrRevoked
		case d.Pub != pub:
			return Device{}, false, fmt.Errorf("%w: a device's key cannot change; use a new device id", ErrConflict)
		case d.Cert != cert:
			_, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_devkeys SET cert=$1 WHERE tenant=$2 AND user_id=$3 AND device=$4`), cert, tenant, user, device)
			d.Cert = cert
			return d, false, err
		}
		return d, false, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Device{}, false, err
	}
	if maxDevices > 0 {
		var n int
		if err := s.db.QueryRowContext(ctx, s.rebind(`SELECT COUNT(*) FROM rtc_devkeys WHERE tenant=$1 AND user_id=$2 AND revoked=0`), tenant, user).Scan(&n); err != nil {
			return Device{}, false, err
		}
		if n >= maxDevices {
			return Device{}, false, fmt.Errorf("%w: at most %d devices per user; revoke one first", ErrLimit, maxDevices)
		}
	}
	now := s.o.Now().UTC()
	_, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_devkeys (tenant, user_id, device, pub, cert, created_at) VALUES ($1,$2,$3,$4,$5,$6)`), tenant, user, device, pub, cert, now.UnixMilli())
	if err != nil {
		if dbx.IsDuplicate(err) { // two publishes at once
			d, gerr := get()
			return d, false, gerr
		}
		return Device{}, false, err
	}
	return Device{User: user, Device: device, Pub: pub, Cert: cert, Created: time.UnixMilli(now.UnixMilli()).UTC()}, true, nil
}

func (s *Store) device(ctx context.Context, tenant, user, device string) (Device, error) {
	d := Device{User: user, Device: device}
	var at int64
	var rev int
	err := s.db.QueryRowContext(ctx, s.rebind(`SELECT pub, cert, created_at, revoked FROM rtc_devkeys WHERE tenant=$1 AND user_id=$2 AND device=$3`), tenant, user, device).Scan(&d.Pub, &d.Cert, &at, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	d.Created, d.Revoked = time.UnixMilli(at).UTC(), rev != 0
	return d, err
}

// Device returns one device, revoked or not.
func (s *Store) Device(ctx context.Context, tenant, user, device string) (Device, error) {
	return s.device(ctx, tenant, user, device)
}

// RevokeDevice retires a device: it is no longer listed, no key is wrapped for
// it, and the ones already wrapped for it are deleted. A device that never
// published is recorded as revoked so it cannot publish later. It reports
// whether the device was active.
func (s *Store) RevokeDevice(ctx context.Context, tenant, user, device string) (bool, error) {
	if !ValidDeviceID(device) {
		return false, ErrInvalid
	}
	r, err := s.db.ExecContext(ctx, s.rebind(`UPDATE rtc_devkeys SET revoked=1 WHERE tenant=$1 AND user_id=$2 AND device=$3 AND revoked=0`), tenant, user, device)
	if err != nil {
		return false, err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		_, err := s.db.ExecContext(ctx, s.rebind(`INSERT INTO rtc_devkeys (tenant, user_id, device, pub, cert, created_at, revoked) VALUES ($1,$2,$3,'','',$4,1)`), tenant, user, device, s.o.Now().UnixMilli())
		if err != nil && !dbx.IsDuplicate(err) {
			return false, err
		}
	}
	if _, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_epoch_keys WHERE tenant=$1 AND user_id=$2 AND device=$3`), tenant, user, device); err != nil {
		return n > 0, err
	}
	return n > 0, nil
}

// Devices returns the active devices of the users.
func (s *Store) Devices(ctx context.Context, tenant string, users []string) ([]Device, error) {
	var out []Device
	for i := 0; i < len(users); i += 200 {
		part := users[i:min(i+200, len(users))]
		q, args := inList(`SELECT user_id, device, pub, cert, created_at FROM rtc_devkeys WHERE tenant=$1 AND revoked=0 AND user_id IN (`, []any{tenant}, part)
		rows, err := s.db.QueryContext(ctx, s.rebind(q), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var d Device
			var at int64
			if err := rows.Scan(&d.User, &d.Device, &d.Pub, &d.Cert, &at); err != nil {
				rows.Close()
				return nil, err
			}
			d.Created = time.UnixMilli(at).UTC()
			out = append(out, d)
		}
		rows.Close()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		return out[i].Device < out[j].Device
	})
	return out, nil
}

// ---------------------------------------------------------------------------
// Epochs.
// ---------------------------------------------------------------------------

// Wrap is a conversation key sealed for one device.
type Wrap struct {
	User   string `json:"user"`
	Device string `json:"device"`
	W      string `json:"w"`
}

// WrapOut is a wrap as its recipient receives it, with who made it and the
// public key to open it with.
type WrapOut struct {
	Epoch     int64  `json:"epoch"`
	By        string `json:"by"`
	ByDevice  string `json:"by_device"`
	ByPub     string `json:"by_pub,omitempty"`
	ByCert    string `json:"by_cert,omitempty"`
	ByRevoked bool   `json:"by_revoked,omitempty"`
	W         string `json:"w"`
}

// checkWraps makes sure every wrap is for an active device of a current member,
// and returns the members that have none.
func (s *Store) checkWraps(ctx context.Context, tenant, by, byDevice string, wraps []Wrap, members []string) (missing []string, err error) {
	devs, err := s.Devices(ctx, tenant, members)
	if err != nil {
		return nil, err
	}
	active := make(map[string]bool, len(devs))
	for _, d := range devs {
		active[d.User+"\x00"+d.Device] = true
	}
	if !active[by+"\x00"+byDevice] {
		return nil, fmt.Errorf("%w: the sending device is not one of yours that is published and active", ErrInvalid)
	}
	covered := map[string]bool{}
	seen := map[string]bool{}
	for _, w := range wraps {
		k := w.User + "\x00" + w.Device
		if w.W == "" || len(w.W) > MaxWrap {
			return nil, fmt.Errorf("%w: a wrap is 1 to %d characters", ErrInvalid, MaxWrap)
		}
		if !active[k] {
			return nil, fmt.Errorf("%w: %s/%s is not an active device of a member", ErrInvalid, w.User, w.Device)
		}
		if seen[k] {
			return nil, fmt.Errorf("%w: %s/%s appears twice", ErrInvalid, w.User, w.Device)
		}
		seen[k] = true
		covered[w.User] = true
	}
	for _, m := range members {
		if !covered[m] {
			missing = append(missing, m)
		}
	}
	return missing, nil
}

func (s *Store) insertWraps(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, tenant, conv string, epoch int64, by, byDevice string, wraps []Wrap) error {
	at := s.o.Now().UnixMilli()
	for i := 0; i < len(wraps); i += 100 {
		part := wraps[i:min(i+100, len(wraps))]
		var sb strings.Builder
		sb.WriteString(`INSERT INTO rtc_epoch_keys (tenant, conv, epoch, user_id, device, by_user, by_device, w, created_at) VALUES `)
		args := make([]any, 0, len(part)*9)
		for j, w := range part {
			if j > 0 {
				sb.WriteByte(',')
			}
			b := len(args)
			fmt.Fprintf(&sb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)", b+1, b+2, b+3, b+4, b+5, b+6, b+7, b+8, b+9)
			args = append(args, tenant, conv, epoch, w.User, w.Device, by, byDevice, w.W, at)
		}
		if _, err := q.ExecContext(ctx, s.rebind(sb.String()), args...); err != nil {
			return err
		}
	}
	return nil
}

// Rotate starts epoch `next` (which must be the current epoch plus one) with the
// key wrapped for the devices of the current members. It fails with ErrStale if
// another member got there first, and with *MissingKeys if a member has no
// device to wrap for. On success the conversation no longer needs a rekey.
func (s *Store) Rotate(ctx context.Context, tenant, conv string, next int64, by, byDevice string, wraps []Wrap, members []string) error {
	if next < 1 {
		return ErrInvalid
	}
	missing, err := s.checkWraps(ctx, tenant, by, byDevice, wraps, members)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return &MissingKeys{Users: missing}
	}
	if err := s.ensureConv(ctx, tenant, conv); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, s.rebind(`UPDATE rtc_conv SET epoch=$1, rekey=0, updated_at=$2 WHERE tenant=$3 AND conv=$4 AND epoch=$5`), next, s.o.Now().UnixMilli(), tenant, conv, next-1)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrStale
	}
	if err := s.insertWraps(ctx, tx, tenant, conv, next, by, byDevice, wraps); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.dropState(tenant, conv)
	return nil
}

// Grant adds wraps of an existing epoch for devices that do not have one yet (a
// member who joined, a new device). A wrap already stored is left as it is. It
// reports how many were added.
func (s *Store) Grant(ctx context.Context, tenant, conv string, epoch int64, by, byDevice string, wraps []Wrap, members []string) (int, error) {
	st, err := s.Fresh(ctx, tenant, conv)
	if err != nil {
		return 0, err
	}
	if epoch < 1 || epoch > st.Epoch {
		return 0, fmt.Errorf("%w: there is no epoch %d", ErrInvalid, epoch)
	}
	if _, err := s.checkWraps(ctx, tenant, by, byDevice, wraps, members); err != nil {
		return 0, err
	}
	have := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT user_id, device FROM rtc_epoch_keys WHERE tenant=$1 AND conv=$2 AND epoch=$3`), tenant, conv, epoch)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var u, d string
		if err := rows.Scan(&u, &d); err != nil {
			rows.Close()
			return 0, err
		}
		have[u+"\x00"+d] = true
	}
	rows.Close()
	var fresh []Wrap
	for _, w := range wraps {
		if !have[w.User+"\x00"+w.Device] {
			fresh = append(fresh, w)
		}
	}
	if len(fresh) == 0 {
		return 0, nil
	}
	if err := s.insertWraps(ctx, s.db, tenant, conv, epoch, by, byDevice, fresh); err != nil {
		if !dbx.IsDuplicate(err) {
			return 0, err
		}
		// Someone granted some of them at the same moment: one by one, keeping what lands.
		n := 0
		for _, w := range fresh {
			if err := s.insertWraps(ctx, s.db, tenant, conv, epoch, by, byDevice, []Wrap{w}); err == nil {
				n++
			} else if !dbx.IsDuplicate(err) {
				return n, err
			}
		}
		return n, nil
	}
	return len(fresh), nil
}

// MyWraps returns the wraps for one device, newest epoch first, for epochs after
// `since`.
func (s *Store) MyWraps(ctx context.Context, tenant, conv, user, device string, since int64) ([]WrapOut, error) {
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT epoch, by_user, by_device, w FROM rtc_epoch_keys WHERE tenant=$1 AND conv=$2 AND user_id=$3 AND device=$4 AND epoch>$5 ORDER BY epoch DESC LIMIT 100`),
		tenant, conv, user, device, since)
	if err != nil {
		return nil, err
	}
	var out []WrapOut
	for rows.Next() {
		var w WrapOut
		if err := rows.Scan(&w.Epoch, &w.By, &w.ByDevice, &w.W); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, w)
	}
	rows.Close()
	cache := map[string]Device{}
	for i := range out {
		k := out[i].By + "\x00" + out[i].ByDevice
		d, ok := cache[k]
		if !ok {
			d, _ = s.device(ctx, tenant, out[i].By, out[i].ByDevice)
			cache[k] = d
		}
		out[i].ByPub, out[i].ByCert, out[i].ByRevoked = d.Pub, d.Cert, d.Revoked
	}
	return out, nil
}

// Missing returns the active devices of the members that have no wrap of the
// current epoch, which is whom a member has to grant the key to.
func (s *Store) Missing(ctx context.Context, tenant, conv string, members []string) (int64, []Device, error) {
	st, err := s.Fresh(ctx, tenant, conv)
	if err != nil || st.Epoch == 0 {
		return st.Epoch, nil, err
	}
	devs, err := s.Devices(ctx, tenant, members)
	if err != nil {
		return st.Epoch, nil, err
	}
	have := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, s.rebind(`SELECT user_id, device FROM rtc_epoch_keys WHERE tenant=$1 AND conv=$2 AND epoch=$3`), tenant, conv, st.Epoch)
	if err != nil {
		return st.Epoch, nil, err
	}
	for rows.Next() {
		var u, d string
		if err := rows.Scan(&u, &d); err != nil {
			rows.Close()
			return st.Epoch, nil, err
		}
		have[u+"\x00"+d] = true
	}
	rows.Close()
	var out []Device
	for _, d := range devs {
		if !have[d.User+"\x00"+d.Device] {
			out = append(out, d)
		}
	}
	return st.Epoch, out, nil
}

// DropWraps deletes the wraps held for users of a conversation, when they leave.
func (s *Store) DropWraps(ctx context.Context, tenant, conv string, users []string) error {
	for _, u := range users {
		if _, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM rtc_epoch_keys WHERE tenant=$1 AND conv=$2 AND user_id=$3`), tenant, conv, u); err != nil {
			return err
		}
	}
	return nil
}
