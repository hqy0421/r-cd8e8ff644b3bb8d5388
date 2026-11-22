// Command audittables produces a per-table readability audit of SQLite files.
//
// For every table it walks the btree page by page, decodes every row, and
// counts how many rows are readable. If a table cannot be read completely it
// records the last readable business key and the page it was on. Indexes are
// walked as well; when index keys are still readable but the base rows are
// not, that is reported in the table's line.
//
// usage:
//   go run ./cmd/audittables [-text] file.sqlite [file2.sqlite ...]
//
// Arguments which are shell glob patterns (testdata/*.sqlite) are expanded.
// The default output is one TSV record per table, suitable for further
// processing. -text prints a human readable report.
package main

import (
	"encoding/binary"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	sdb "github.com/alicebob/sqlittle/db"
	"github.com/alicebob/sqlittle/sql"
)

type column struct {
	name  string
	rowid bool // alias for the rowid; not stored in the record
}

type tableInfo struct {
	name    string
	root    int
	without bool
	cols    []column // definition order
	store   []int    // storage position -> index into cols
	pk      []string // business key column names
	pkName  string   // name of the rowid alias column, if any
	pkRowid bool     // business key is the rowid
	schema  bool     // CREATE TABLE parsed
	err     error    // schema parse error
}

type indexInfo struct {
	name string
	root int
	cols []string // indexed column names, in stored order (nil if unknown)
}

func main() {
	text := flag.Bool("text", false, "human readable output")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [-text] file.sqlite...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	var files []string
	for _, a := range flag.Args() {
		if fs, err := filepath.Glob(a); err == nil && len(fs) > 0 {
			files = append(files, fs...)
			continue
		}
		files = append(files, a)
	}
	sort.Strings(files)

	w := csv.NewWriter(os.Stdout)
	w.Comma = '\t'
	if !*text {
		w.Write([]string{
			"file", "table", "kind", "status", "readable_rows",
			"last_key", "last_page", "error", "note",
		})
	}
	for _, f := range files {
		auditFile(f, *text, w)
	}
	w.Flush()
}

func auditFile(file string, text bool, w *csv.Writer) {
	if text {
		fmt.Printf("== %s\n", file)
	}

	if note := truncation(file); note != "" {
		emit(w, text, file, "-", "file", "TRUNCATED", 0, "", "", note,
			"file is shorter than the page count in its header; pages beyond the end of the file cannot be read")
	}

	db, err := sdb.OpenFile(file)
	if err != nil {
		note := "cannot open database"
		switch {
		case err == sdb.ErrWAL:
			if _, serr := os.Stat(file + "-wal"); serr == nil {
				note = "database is in WAL mode and a -wal file is present; the main file alone is not the committed state, open it with sqlite3 (which checkpoints the WAL) before importing"
			} else {
				note = "database is in WAL mode; the main file is not the committed state, convert to journal mode (sqlite3 'PRAGMA journal_mode=DELETE') before importing"
			}
		case err == sdb.ErrHotJournal:
			note = "a hot journal is present; the main file is not the committed state, open it with sqlite3 to roll the transaction back before importing"
		}
		emit(w, text, file, "-", "database", "UNREADABLE", 0, "", "", err.Error(), note)
		return
	}
	defer db.Close()

	ma, err := db.AuditMaster()
	if err != nil {
		emit(w, text, file, "sqlite_master", "schema", "UNREADABLE", 0, "", "", err.Error(), "cannot read sqlite_master")
		return
	}
	if !ma.Complete() {
		var msgs []string
		for _, p := range ma.Problems {
			msgs = append(msgs, p.String())
		}
		emit(w, text, file, "sqlite_master", "schema", "PARTIAL",
			len(ma.Entries), "", "", strings.Join(msgs, "; "),
			fmt.Sprintf("%d undecodable schema cell(s); objects found in the readable cells are listed below", len(ma.Problems)))
	}

	var tables []tableInfo
	for _, e := range ma.Entries {
		if e.Err != nil || e.Type != "table" {
			continue
		}
		tables = append(tables, tableInfoOf(e))
	}

	byTable := map[string][]indexInfo{}
	for _, e := range ma.Entries {
		if e.Err != nil || e.Type != "index" {
			continue
		}
		ix := indexInfo{name: e.Name, root: e.RootPage}
		if stmt, err := sql.Parse(strings.TrimSpace(e.SQL)); err == nil {
			if ci, ok := stmt.(sql.CreateIndexStmt); ok {
				for _, c := range ci.IndexedColumns {
					ix.cols = append(ix.cols, c.Column)
				}
			}
		}
		byTable[strings.ToLower(e.TblName)] = append(byTable[strings.ToLower(e.TblName)], ix)
	}

	for _, ti := range tables {
		auditTable(db, file, ti, byTable[strings.ToLower(ti.name)], text, w)
		delete(byTable, strings.ToLower(ti.name))
	}

	// Indexes whose table has no decodable sqlite_master row (the schema cell
	// itself may be one of the damaged ones). Still audit them: readable index
	// keys are useful to the importer even when the table definition is lost.
	var lost []string
	for name := range byTable {
		lost = append(lost, name)
	}
	sort.Strings(lost)
	for _, name := range lost {
		auditTable(db, file, tableInfo{name: name}, byTable[name], text, w)
	}
}

// truncation compares the file size with the page count in the database
// header. A non-empty description is returned when the file is shorter than
// the header claims; that is the cause of EOF and out-of-range page numbers.
// Files which are not SQLite (or too short to hold a header) return "".
func truncation(file string) string {
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()
	var hdr [100]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return ""
	}
	if string(hdr[:16]) != "SQLite format 3\x00" {
		return ""
	}
	ps := int(binary.BigEndian.Uint16(hdr[16:18]))
	if ps == 1 {
		ps = 1 << 16
	}
	if ps < 512 || ps > 1<<16 || ps&(ps-1) != 0 {
		return ""
	}
	pages := int(binary.BigEndian.Uint32(hdr[28:32]))
	if pages <= 0 || pages > 1<<30 {
		// An absurd page count means the header itself is damaged; that is
		// reported by OpenFile, and calling the file "truncated" would be
		// misleading.
		return ""
	}
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	have := int(st.Size()) / ps
	if have < 1 || have >= pages {
		return ""
	}
	return fmt.Sprintf("header declares %d pages (%d bytes), file holds %d (%d bytes)",
		pages, pages*ps, have, st.Size())
}

func tableInfoOf(e sdb.MasterEntry) tableInfo {
	ti := tableInfo{name: e.Name, root: e.RootPage}
	sqlText := strings.TrimSpace(e.SQL)
	if sqlText == "" {
		return ti
	}
	stmt, err := sql.Parse(sqlText)
	if err != nil {
		ti.err = err
		return ti
	}
	ct, ok := stmt.(sql.CreateTableStmt)
	if !ok {
		ti.err = fmt.Errorf("not a CREATE TABLE statement")
		return ti
	}
	ti.schema = true
	ti.without = ct.WithoutRowid

	for _, c := range ct.Columns {
		col := column{name: c.Name}
		if c.PrimaryKey && !ct.WithoutRowid && isRowidAlias(c.Type, c.PrimaryKeyDir, false) {
			col.rowid = true
			ti.pkRowid = true
			ti.pkName = c.Name
			ti.pk = []string{c.Name}
		}
		ti.cols = append(ti.cols, col)
	}
	for _, con := range ct.Constraints {
		pk, ok := con.(sql.TablePrimaryKey)
		if !ok {
			continue
		}
		var names []string
		for _, ic := range pk.IndexedColumns {
			names = append(names, ic.Column)
		}
		ti.pk = names
		if !ct.WithoutRowid && len(names) == 1 {
			if isRowidAlias(columnType(ct, names[0]), pk.IndexedColumns[0].SortOrder, true) {
				ti.pkRowid = true
				ti.pkName = names[0]
				for i := range ti.cols {
					if strings.EqualFold(ti.cols[i].name, names[0]) {
						ti.cols[i].rowid = true
					}
				}
			}
		}
	}
	for _, c := range ct.Columns {
		if c.PrimaryKey && len(ti.pk) == 0 {
			ti.pk = []string{c.Name}
		}
	}

	ti.store = storeOrder(ti)
	return ti
}

// storeOrder returns, for each position in a stored record, the index into
// ti.cols. Rowid columns are not stored at all. WITHOUT ROWID records store the
// primary key columns first, then the remaining columns in definition order.
func storeOrder(ti tableInfo) []int {
	var order []int
	if ti.without {
		for _, name := range ti.pk {
			for i, c := range ti.cols {
				if strings.EqualFold(c.name, name) {
					order = append(order, i)
				}
			}
		}
	}
	for i, c := range ti.cols {
		if c.rowid || containsInt(order, i) {
			continue
		}
		order = append(order, i)
	}
	return order
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func columnType(ct sql.CreateTableStmt, name string) string {
	for _, c := range ct.Columns {
		if strings.EqualFold(c.Name, name) {
			return c.Type
		}
	}
	return ""
}

// isRowidAlias mirrors db.isRowid: a single column of type INTEGER is an alias
// for the rowid. For a column constraint only ASC works; a table constraint
// allows ASC and DESC.
func isRowidAlias(typ string, dir sql.SortOrder, tableConstraint bool) bool {
	if !strings.EqualFold(strings.TrimSpace(typ), "INTEGER") {
		return false
	}
	return tableConstraint || dir == sql.Asc
}

func auditTable(db *sdb.Database, file string, ti tableInfo, indexes []indexInfo, text bool, w *csv.Writer) {
	// Collect the rowids of the base table while walking it, so index keys
	// can be checked against the rows which really are readable.
	readableRowids := map[int64]bool{}
	var base *sdb.AuditWalk
	if ti.root <= 0 {
		// The CREATE TABLE row itself was damaged: the root page of the base
		// btree is unknown, but indexes on the table may still be listed and
		// readable.
		base = &sdb.AuditWalk{Kind: sdb.AuditTable, LastRowid: -1}
		base.Problems = []sdb.AuditProblem{{
			Page: 0, Cell: -1,
			Err: fmt.Errorf("base table definition is not readable (no decodable sqlite_master row); root page unknown"),
		}}
	} else {
		base = db.AuditRoot(ti.root, func(_ int, rowid int64, _ sdb.Record) {
			if rowid >= 0 {
				readableRowids[rowid] = true
			}
		})
	}

	kind := "table"
	if ti.without {
		kind = "without-rowid"
	}
	status := "COMPLETE"
	if !base.Complete() {
		status = "INCOMPLETE"
	}
	if base.Rows == 0 && !base.Complete() {
		status = "UNREADABLE"
	}

	var notes []string
	if ti.without {
		notes = append(notes, "WITHOUT ROWID; base rows live in an index btree")
	}
	if !ti.schema && ti.err != nil {
		notes = append(notes, "schema unparsable: "+ti.err.Error())
	}
	for _, w := range base.Warnings {
		notes = append(notes, "warning: "+w)
	}

	// Walk every index of this table. Index keys may still be readable even
	// when the base rows are not.
	type idxResult struct {
		info   indexInfo
		walk   *sdb.AuditWalk
		orphan int // keys with no readable base row
	}
	var ires []idxResult
	for _, ix := range indexes {
		iw := db.AuditRoot(ix.root, nil)
		r := idxResult{info: ix, walk: iw}
		// An index on a rowid table ends with the rowid as last field. When
		// that rowid is not among the readable base rows the key is dangling.
		if iw.Kind == sdb.AuditIndex && !ti.without && base.Kind == sdb.AuditTable {
			db.AuditRoot(ix.root, func(_ int, _ int64, rec sdb.Record) {
				rowid, _, err := sdb.ChompRowid(rec)
				if err != nil {
					return
				}
				if !readableRowids[rowid] {
					r.orphan++
				}
			})
		}
		ires = append(ires, r)
	}

	if len(ires) > 0 {
		var parts []string
		for _, r := range ires {
			state := fmt.Sprintf("%s=%d keys", r.info.name, r.walk.Rows)
			if !r.walk.Complete() {
				state = fmt.Sprintf("%s stopped after %d keys (%s)", r.info.name, r.walk.Rows, r.walk.FirstProblem())
			}
			if r.orphan > 0 {
				state += fmt.Sprintf(", %d key(s) without readable base row", r.orphan)
			}
			parts = append(parts, state)
		}
		if status != "COMPLETE" {
			var readable []string
			for _, r := range ires {
				if r.walk.Complete() && r.walk.Rows > 0 {
					readable = append(readable, r.info.name)
				}
			}
			if len(readable) > 0 {
				if base.Rows == 0 {
					notes = append(notes, "no base row is readable, but index keys are readable in: "+strings.Join(readable, ", "))
				} else {
					notes = append(notes, fmt.Sprintf("base rows only partially readable (%d row(s)); index keys are readable in: %s",
						base.Rows, strings.Join(readable, ", ")))
				}
			}
		}
		var unreadable []string
		for _, r := range ires {
			if !r.walk.Complete() {
				unreadable = append(unreadable, r.info.name)
			}
		}
		if len(unreadable) > 0 && status == "COMPLETE" {
			notes = append(notes, "base rows fully readable but index keys unusable in: "+strings.Join(unreadable, ", "))
		}
		notes = append(notes, "indexes: "+strings.Join(parts, "; "))
	}

	var lastKey, lastPage, errMsg string
	if status != "COMPLETE" {
		if p := base.FirstProblem(); p != nil {
			errMsg = p.String()
		}
		if base.Rows > 0 {
			lastKey = businessKey(ti, base.Last, base.LastRowid, 60)
			lastPage = fmt.Sprintf("%d", base.LastPage)
		}
		// How many rows are still decodable if the bad cells are skipped?
		// That tells the importer whether a repair/partial import can recover
		// more than the contiguous prefix counted above.
		if sv := db.AuditSalvage(ti.root); sv.Rows > base.Rows {
			notes = append(notes, fmt.Sprintf(
				"%d row(s) decode if the %d damaged cell(s)/page(s) are skipped; only the first %d form a contiguous importable prefix",
				sv.Rows, len(sv.Problems), base.Rows))
		}
	}

	emit(w, text, file, ti.name, kind, status, base.Rows, lastKey, lastPage, errMsg, strings.Join(notes, "; "))

	if text {
		for _, r := range ires {
			st := "COMPLETE"
			if !r.walk.Complete() {
				st = "INCOMPLETE"
			}
			var ierr string
			if p := r.walk.FirstProblem(); p != nil {
				ierr = p.String()
			}
			var last string
			var page string
			if !r.walk.Complete() && r.walk.Rows > 0 {
				last = indexKey(r.info, r.walk.Last, 60)
				page = fmt.Sprintf("%d", r.walk.LastPage)
			}
			fmt.Printf("    index  %-40s %-10s keys=%-6d", r.info.name, st, r.walk.Rows)
			if last != "" {
				fmt.Printf(" last=%s@%s", last, page)
			}
			if ierr != "" {
				fmt.Printf(" err=%q", ierr)
			}
			fmt.Println()
		}
	}
}

// businessKey formats the primary key of a stored row, or the whole record if
// there is no primary key.
func businessKey(ti tableInfo, rec sdb.Record, rowid int64, limit int) string {
	if rec == nil {
		return ""
	}
	if ti.pkRowid {
		name := ti.pkName
		if name == "" {
			name = "rowid"
		}
		return fmt.Sprintf("%s=%d", name, rowid)
	}
	if len(ti.pk) == 0 || !ti.schema {
		return recordString(rec, limit)
	}
	var parts []string
	for _, name := range ti.pk {
		v, ok := pkValue(ti, rec, rowid, name)
		if !ok {
			return recordString(rec, limit)
		}
		parts = append(parts, fmt.Sprintf("%s=%s", name, valueString(v, limit)))
	}
	return strings.Join(parts, ",")
}

func pkValue(ti tableInfo, rec sdb.Record, rowid int64, name string) (interface{}, bool) {
	// storage position -> column index
	for pos, ci := range ti.store {
		if !strings.EqualFold(ti.cols[ci].name, name) {
			continue
		}
		if pos >= len(rec) {
			return nil, false
		}
		return rec[pos], true
	}
	// Column is an alias for the rowid.
	for _, c := range ti.cols {
		if strings.EqualFold(c.name, name) && c.rowid {
			return rowid, true
		}
	}
	return nil, false
}

func indexKey(ix indexInfo, rec sdb.Record, limit int) string {
	if len(ix.cols) == 0 {
		return recordString(rec, limit)
	}
	var parts []string
	for i, name := range ix.cols {
		if i >= len(rec) {
			break
		}
		parts = append(parts, fmt.Sprintf("%s=%s", name, valueString(rec[i], limit)))
	}
	return strings.Join(parts, ",")
}

func recordString(rec sdb.Record, limit int) string {
	var parts []string
	for _, v := range rec {
		parts = append(parts, valueString(v, limit))
	}
	return strings.Join(parts, "|")
}

func valueString(v interface{}, limit int) string {
	var s string
	switch v := v.(type) {
	case nil:
		s = "NULL"
	case string:
		s = v
	case []byte:
		if len(v) > 16 {
			s = fmt.Sprintf("%x...(%d bytes)", v[:16], len(v))
		} else {
			s = fmt.Sprintf("%x", v)
		}
	case int64:
		s = fmt.Sprintf("%d", v)
	case float64:
		s = fmt.Sprintf("%g", v)
	default:
		s = fmt.Sprintf("%v", v)
	}
	if limit > 0 && len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}

func emit(w *csv.Writer, text bool, file, object, kind, status string, rows int, lastKey, lastPage, errMsg, note string) {
	if text {
		fmt.Printf("  %-14s %-32s %-10s rows=%-6d", kind, object, status, rows)
		if lastKey != "" {
			fmt.Printf(" last=%s@%s", lastKey, lastPage)
		}
		if errMsg != "" {
			fmt.Printf(" err=%q", errMsg)
		}
		if note != "" {
			fmt.Printf(" [%s]", note)
		}
		fmt.Println()
		return
	}
	w.Write([]string{
		file, object, kind, status, fmt.Sprintf("%d", rows),
		lastKey, lastPage, errMsg, note,
	})
}
