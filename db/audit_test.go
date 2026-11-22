package db

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// rootOf returns the root page of the named object from sqlite_master.
func rootOf(t *testing.T, db *Database, name string) int {
	t.Helper()
	ma, err := db.AuditMaster()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ma.Entries {
		if e.Err == nil && strings.EqualFold(e.Name, name) {
			return e.RootPage
		}
	}
	t.Fatalf("no such object in sqlite_master: %q", name)
	return 0
}

func TestAuditMasterWords(t *testing.T) {
	db, err := OpenFile("./../testdata/words.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ma, err := db.AuditMaster()
	if err != nil {
		t.Fatal(err)
	}
	if !ma.Complete() {
		t.Fatalf("sqlite_master incomplete: %v", ma.Problems)
	}
	// table + two indexes
	if have, want := len(ma.Entries), 3; have != want {
		t.Errorf("have %d entries, want %d", have, want)
	}
	if have, want := ma.Entries[0].Type, "table"; have != want {
		t.Errorf("have %q, want %q", have, want)
	}
}

func TestAuditMasterDamaged(t *testing.T) {
	// issue_1 has a sqlite_master with a single cell which decodes to four
	// fields; the whole table must not be thrown away, but the cell has to be
	// reported.
	db, err := OpenFile("./../testdata/issue_1.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ma, err := db.AuditMaster()
	if err != nil {
		t.Fatal(err)
	}
	if ma.Complete() {
		t.Fatal("expected sqlite_master problems")
	}
	if have, want := len(ma.Problems), 1; have != want {
		t.Fatalf("have %d problems, want %d", have, want)
	}
	if have, want := ma.Problems[0].Page, 1; have != want {
		t.Errorf("have page %d, want %d", have, want)
	}
}

func TestAuditTableComplete(t *testing.T) {
	db, err := OpenFile("./../testdata/words.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	root := rootOf(t, db, "words")
	w := db.AuditRoot(root, nil)
	if !w.Complete() {
		t.Fatalf("problems: %v", w.Problems)
	}
	if have, want := w.Rows, 1000; have != want {
		t.Errorf("have %d rows, want %d", have, want)
	}
	if have, want := w.Kind, AuditTable; have != want {
		t.Errorf("have kind %q, want %q", have, want)
	}
	if have, want := len(w.Last), 2; have != want {
		t.Errorf("last record has %d fields, want %d", have, want)
	}
}

func TestAuditIndexComplete(t *testing.T) {
	db, err := OpenFile("./../testdata/words.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	root := rootOf(t, db, "words_index_1")
	w := db.AuditRoot(root, nil)
	if !w.Complete() {
		t.Fatalf("problems: %v", w.Problems)
	}
	if have, want := w.Rows, 1000; have != want {
		t.Errorf("have %d keys, want %d", have, want)
	}
	if have, want := w.Kind, AuditIndex; have != want {
		t.Errorf("have kind %q, want %q", have, want)
	}
	if have, want := w.LastRowid, int64(-1); have != want {
		t.Errorf("have last rowid %d, want %d", have, want)
	}
}

// TestAuditTableFrontier checks that a damaged table reports the last readable
// row and the page it was on.
func TestAuditTableFrontier(t *testing.T) {
	// Truncate northwind so that reading stops part-way through "Order".
	buf, err := os.ReadFile("./../testdata/northwind.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	fn := filepath.Join(dir, "trunc.sqlite")
	if err := os.WriteFile(fn, buf[:60000], 0600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	w := db.AuditRoot(rootOf(t, db, "Order"), nil)
	if w.Complete() {
		t.Fatal("expected an incomplete walk")
	}
	if w.Rows == 0 {
		t.Fatal("expected some readable rows")
	}
	if w.FirstProblem() == nil {
		t.Fatal("expected a problem")
	}
	if w.LastPage < 1 || w.LastPage > 283 {
		t.Errorf("last page %d is not a page of the database", w.LastPage)
	}
	// "Id" is an INTEGER PRIMARY KEY, which is stored as the rowid, so the
	// last readable rowid is the business key even though the record itself
	// has no Id field.
	if have, want := w.LastRowid, int64(10289); have != want {
		t.Errorf("have last rowid %d, want %d", have, want)
	}
}

func TestAuditSalvage(t *testing.T) {
	// issue_4 has a leaf page whose first cells have absurd payload lengths,
	// but later cells are still decodable. The strict walk stops immediately;
	// the salvage walk skips the bad cells and finds more rows.
	db, err := OpenFile("./../testdata/issue_4.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	root := rootOf(t, db, "words")

	strict := db.AuditRoot(root, nil)
	if strict.Complete() {
		t.Fatal("expected the strict walk to stop")
	}

	salvage := db.AuditSalvage(root)
	if salvage.Complete() {
		t.Fatal("expected the salvage walk to report problems")
	}
	if salvage.Rows <= strict.Rows {
		t.Errorf("salvage found %d rows, strict found %d; salvage should find more",
			salvage.Rows, strict.Rows)
	}
	if len(salvage.Problems) <= len(strict.Problems) {
		t.Errorf("salvage reported %d problems, strict %d", len(salvage.Problems), len(strict.Problems))
	}
	// The last decodable record must be one of the real words.
	if have, want := len(salvage.Last), 2; have != want {
		t.Errorf("salvage last record has %d fields, want %d", have, want)
	}
}

func TestAuditOverflowWarning(t *testing.T) {
	// 8f7c completes its payload but the last overflow pointer is garbage.
	// The row is readable; sqlite3 still flags the file, so it is a warning.
	db, err := OpenFile("./../corpus/8f7c560dbe751da49644ecbecc7d76ba45e5d4f2-1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	root := rootOf(t, db, "mytable")
	w := db.AuditRoot(root, nil)
	if !w.Complete() {
		t.Fatalf("expected the row to be readable, problems: %v", w.Problems)
	}
	if have, want := w.Rows, 1; have != want {
		t.Errorf("have %d rows, want %d", have, want)
	}
	if have, want := len(w.Warnings), 1; have != want {
		t.Fatalf("have %d warnings, want %d: %v", have, want, w.Warnings)
	}
	if !strings.Contains(w.Warnings[0], "overflow chain continues") {
		t.Errorf("unexpected warning: %q", w.Warnings[0])
	}
}

func TestAuditRootInvalidPage(t *testing.T) {
	db, err := OpenFile("./../testdata/words.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	w := db.AuditRoot(99999, nil)
	if w.Complete() {
		t.Fatal("expected problems for an out of range root page")
	}
	if have, want := w.Rows, 0; have != want {
		t.Errorf("have %d rows, want %d", have, want)
	}
}

func TestAuditWalkWithoutRowid(t *testing.T) {
	// WITHOUT ROWID base rows live in an index btree.
	db, err := OpenFile("./../testdata/withoutrowid.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	root := rootOf(t, db, "words")
	w := db.AuditRoot(root, nil)
	if !w.Complete() {
		t.Fatalf("problems: %v", w.Problems)
	}
	if have, want := w.Rows, 1000; have != want {
		t.Errorf("have %d rows, want %d", have, want)
	}
	if have, want := w.Kind, AuditIndex; have != want {
		t.Errorf("have kind %q, want %q", have, want)
	}
	// Records are stored with the primary key (word) first.
	if have, want := reflect.DeepEqual(w.Last[0], "yeshivahs"), true; have != want {
		t.Errorf("last record: have %#v", w.Last)
	}
}

func TestAuditKindOf(t *testing.T) {
	db, err := OpenFile("./../testdata/funkykey.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	kind, err := db.AuditKindOf(rootOf(t, db, "fuz"))
	if err != nil {
		t.Fatal(err)
	}
	if have, want := kind, AuditIndex; have != want {
		t.Errorf("fuz: have %q, want %q", have, want)
	}
	kind, err = db.AuditKindOf(rootOf(t, db, "sqlite_autoindex_fuz_2"))
	if err != nil {
		t.Fatal(err)
	}
	if have, want := kind, AuditIndex; have != want {
		t.Errorf("autoindex: have %q, want %q", have, want)
	}

	if _, err := db.AuditKindOf(99999); err == nil {
		t.Error("expected an error for an out of range page")
	}
}
