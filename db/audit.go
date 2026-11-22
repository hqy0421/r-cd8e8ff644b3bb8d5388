// Page level integrity audit.
//
// The regular Scan() helpers stop at the first error and only report the
// error, not how far they got or which page they were on. The routines here
// walk a btree page by page, decode every record, and keep track of the last
// record which could be read and the page it lived on. That makes it possible
// to tell, for a damaged database, exactly which rows are still importable.
//
// The walkers are strict: they verify the btree page header, the cell pointer
// array, the cell content area, overflow chains, and the record encoding.
// They never panic on damaged input; a problem is reported instead.
//
// AuditRoot stops at the first problem, which makes its row count the length
// of the contiguous, importable prefix. AuditSalvage keeps going, skipping
// damaged cells, so it reports how much is readable in total.
//
// Audit is read-only and does not interact with the page cache used by the
// normal readers.

package db

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// AuditKind tells which flavour of btree a root page turned out to be.
type AuditKind string

const (
	// AuditTable is a rowid table btree (page types 0x05/0x0d).
	AuditTable AuditKind = "table"
	// AuditIndex is an index btree (page types 0x02/0x0a). A WITHOUT ROWID
	// table also uses this kind of btree for its base rows.
	AuditIndex AuditKind = "index"
)

// AuditProblem is a single page or cell which could not be decoded.
type AuditProblem struct {
	Page int
	Cell int // -1 if the whole page is unusable
	Err  error
}

func (p AuditProblem) String() string {
	if p.Page <= 0 {
		return p.Err.Error()
	}
	if p.Cell < 0 {
		return fmt.Sprintf("page %d: %v", p.Page, p.Err)
	}
	return fmt.Sprintf("page %d cell %d: %v", p.Page, p.Cell, p.Err)
}

// AuditWalk is the result of walking one table or index btree.
//
// The walk returns the records which could be decoded before the first
// problem, in btree order. Rows is their number. Last, LastRowid, and LastPage
// describe the last one, which is the frontier where reading stopped.
// Problems lists what stopped the walk; Complete is true when the whole tree
// could be read.
//
// For index btrees LastRowid is -1. For an interior index page the "record"
// stored in the interior cell is counted as well, in key order.
type AuditWalk struct {
	Kind      AuditKind
	Rows      int
	Last      Record
	LastRowid int64
	LastPage  int
	Problems  []AuditProblem
	// Warnings lists damage which does not prevent reading a record, such as
	// an overflow chain which continues past the end of the payload.
	Warnings []string
}

// Complete reports whether the entire btree could be read.
func (w *AuditWalk) Complete() bool {
	return len(w.Problems) == 0
}

// FirstProblem returns the problem which stopped the walk, or nil.
func (w *AuditWalk) FirstProblem() *AuditProblem {
	if len(w.Problems) == 0 {
		return nil
	}
	return &w.Problems[0]
}

type auditPage struct {
	num   int
	typ   int
	hdr   int // offset of the btree page header (100 on page 1)
	ncell int
	data  []byte // the whole page
}

func (p *auditPage) pageNo() int { return p.num }

func (p *auditPage) isInterior() bool {
	return p.typ == 0x02 || p.typ == 0x05
}

func (p *auditPage) cellOffset(i int) int {
	hdrSize := 8
	if p.isInterior() {
		hdrSize = 12
	}
	return int(binary.BigEndian.Uint16(p.data[p.hdr+hdrSize+2*i:]))
}

func (p *auditPage) interiorRightmost() int {
	return int(binary.BigEndian.Uint32(p.data[p.hdr+8:]))
}

// auditPage reads and validates a page. Page 1 has the 100 byte file header in
// front of the btree page header. Cell offsets and the cell content offset are
// relative to the start of the page, so on page 1 they include the file
// header.
func (db *Database) auditPage(page int) (*auditPage, error) {
	if page < 1 {
		return nil, fmt.Errorf("invalid page number %d", page)
	}
	buf, err := db.page(page)
	if err != nil {
		return nil, err
	}
	if len(buf) != db.header.PageSize {
		return nil, fmt.Errorf("short page (%d of %d bytes)", len(buf), db.header.PageSize)
	}
	hdr := 0
	if page == 1 {
		hdr = headerSize
	}
	typ := int(buf[hdr])
	hdrSize := 0
	switch typ {
	case 0x0d, 0x0a:
		hdrSize = 8
	case 0x05, 0x02:
		hdrSize = 12
	default:
		return nil, fmt.Errorf("unsupported btree page type 0x%02x", typ)
	}
	ncell := int(binary.BigEndian.Uint16(buf[hdr+3:]))
	ptrEnd := hdr + hdrSize + 2*ncell
	if ptrEnd > len(buf) {
		return nil, fmt.Errorf("cell pointer array (%d cells) does not fit in the page", ncell)
	}
	if ncell > 0 {
		contentStart := int(binary.BigEndian.Uint16(buf[hdr+5:]))
		if contentStart == 0 && db.header.PageSize == 1<<16 {
			// A cell content offset of 0 encodes 65536 for 64K pages.
			contentStart = 1 << 16
		}
		if contentStart < ptrEnd || contentStart > len(buf) {
			return nil, fmt.Errorf(
				"invalid cell content start %d (cell pointer array ends at %d, page is %d bytes)",
				contentStart, ptrEnd, len(buf),
			)
		}
	}
	return &auditPage{num: page, typ: typ, hdr: hdr, ncell: ncell, data: buf}, nil
}

// checkCell validates the cell pointer for cell i. Cell pointer arrays are not
// necessarily sorted, so this only checks that each pointer points into the
// cell content area of the page.
func (p *auditPage) checkCell(i int) error {
	ptrEnd := p.hdr + 8 + 2*p.ncell
	if p.isInterior() {
		ptrEnd += 4
	}
	cp := p.cellOffset(i)
	if cp < ptrEnd || cp >= len(p.data) {
		return fmt.Errorf(
			"cell %d pointer %d outside the cell content area [%d,%d)",
			i, cp, ptrEnd, len(p.data),
		)
	}
	return nil
}

// AuditKindOf reports whether root is a table or an index btree without walking
// it.
func (db *Database) AuditKindOf(root int) (AuditKind, error) {
	if err := db.resolveDirty(); err != nil {
		return "", err
	}
	p, err := db.auditPage(root)
	if err != nil {
		return "", err
	}
	if p.typ == 0x0a || p.typ == 0x02 {
		return AuditIndex, nil
	}
	return AuditTable, nil
}

// AuditRoot walks the btree starting at root, page by page, in key order. cb,
// if not nil, is called for every decoded record with the page the record
// lives on and its rowid (rowid is -1 for index btrees).
//
// The walk stops at the first page or cell which cannot be decoded; the
// returned AuditWalk records everything decoded up to that point. The caller
// must hold a read lock if the database may be modified concurrently.
func (db *Database) AuditRoot(root int, cb func(page int, rowid int64, rec Record)) *AuditWalk {
	w := &AuditWalk{Kind: AuditTable, LastRowid: -1}
	if err := db.resolveDirty(); err != nil {
		w.fail(root, -1, err)
		return w
	}
	p, err := db.auditPage(root)
	if err != nil {
		w.fail(root, -1, err)
		return w
	}
	if p.typ == 0x0a || p.typ == 0x02 {
		w.Kind = AuditIndex
	}
	a := &auditor{db: db, w: w, cb: cb, seen: map[int]bool{}}
	if w.Kind == AuditIndex {
		a.indexPage(root, maxRecursion)
	} else {
		a.tablePage(root, maxRecursion)
	}
	return w
}

// AuditSalvage walks like AuditRoot, but does not stop at the first bad cell:
// it skips the undecodable cell (or the unreadable branch) and continues with
// the rest of the btree. The returned walk's Rows is the total number of
// records which could be decoded, which may be larger than the number of rows
// which form a contiguous, importable prefix (that is what AuditRoot reports).
// Problems lists every cell which had to be skipped.
//
// A root page which cannot be read at all still yields an empty walk.
func (db *Database) AuditSalvage(root int) *AuditWalk {
	w := &AuditWalk{Kind: AuditTable, LastRowid: -1}
	if err := db.resolveDirty(); err != nil {
		w.fail(root, -1, err)
		return w
	}
	p, err := db.auditPage(root)
	if err != nil {
		w.fail(root, -1, err)
		return w
	}
	if p.typ == 0x0a || p.typ == 0x02 {
		w.Kind = AuditIndex
	}
	a := &auditor{db: db, w: w, seen: map[int]bool{}, salvage: true}
	if w.Kind == AuditIndex {
		a.indexPage(root, maxRecursion)
	} else {
		a.tablePage(root, maxRecursion)
	}
	return w
}

type auditor struct {
	db      *Database
	w       *AuditWalk
	cb      func(int, int64, Record)
	seen    map[int]bool
	stop    bool
	salvage bool
}

func (w *AuditWalk) fail(page, cell int, err error) {
	w.Problems = append(w.Problems, AuditProblem{Page: page, Cell: cell, Err: err})
}

// fail records a problem. In strict mode it also stops the walk; in salvage
// mode the caller moves on to the next cell.
func (a *auditor) fail(page, cell int, err error) bool {
	a.w.fail(page, cell, err)
	if !a.salvage {
		a.stop = true
	}
	return false
}

func (a *auditor) record(page int, rowid int64, rec Record) {
	a.w.Rows++
	a.w.Last = rec
	a.w.LastRowid = rowid
	a.w.LastPage = page
	if a.cb != nil {
		a.cb(page, rowid, rec)
	}
}

// openPage reads and classifies page, checking it against the btree kind we
// expect. It returns a descriptive error on failure.
func (a *auditor) openPage(page int, index bool) (*auditPage, error) {
	if a.seen[page] {
		return nil, fmt.Errorf("page is referenced more than once (btree loop)")
	}
	p, err := a.db.auditPage(page)
	if err != nil {
		return nil, err
	}
	ok := false
	if index {
		ok = p.typ == 0x0a || p.typ == 0x02
	} else {
		ok = p.typ == 0x0d || p.typ == 0x05
	}
	if !ok {
		kind := "table"
		if index {
			kind = "index"
		}
		return nil, fmt.Errorf("expected an %s page, found page type 0x%02x", kind, p.typ)
	}
	a.seen[page] = true
	return p, nil
}

func (a *auditor) tablePage(page, depth int) bool {
	if a.stop {
		return false
	}
	if depth <= 0 {
		return a.fail(page, -1, ErrRecursion)
	}
	p, err := a.openPage(page, false)
	if err != nil {
		return a.fail(page, -1, err)
	}

	if p.typ == 0x0d {
		for i := 0; i < p.ncell; i++ {
			if a.stop {
				return false
			}
			if err := p.checkCell(i); err != nil {
				if !a.skip(page, i, err) {
					return false
				}
				continue
			}
			c, err := parseTableLeaf(p.data[p.cellOffset(i):], a.db.header.PageSize)
			if err == nil {
				var full []byte
				full, err = a.payload(page, c.payload)
				if err == nil {
					var rec Record
					if rec, err = parseRecord(full); err == nil {
						a.record(page, c.left, rec)
						continue
					}
				}
			}
			if !a.skip(page, i, err) {
				return false
			}
		}
		return true
	}

	for i := 0; i < p.ncell; i++ {
		if a.stop {
			return false
		}
		if err := p.checkCell(i); err != nil {
			if !a.skip(page, i, err) {
				return false
			}
			continue
		}
		c, err := parseTableInterior(p.data[p.cellOffset(i):])
		if err != nil {
			if !a.skip(page, i, err) {
				return false
			}
			continue
		}
		if !a.tablePage(c.left, depth-1) && !a.salvage {
			return false
		}
	}
	return a.tablePage(p.interiorRightmost(), depth-1)
}

// skip records a problem and reports whether the walk should go on.
func (a *auditor) skip(page, cell int, err error) bool {
	a.fail(page, cell, err)
	return a.salvage && !a.stop
}

func (a *auditor) indexPage(page, depth int) bool {
	if a.stop {
		return false
	}
	if depth <= 0 {
		return a.fail(page, -1, ErrRecursion)
	}
	p, err := a.openPage(page, true)
	if err != nil {
		return a.fail(page, -1, err)
	}

	record := func(pl cellPayload, cell int) bool {
		full, err := a.payload(page, pl)
		if err == nil {
			var rec Record
			if rec, err = parseRecord(full); err == nil {
				a.record(page, -1, rec)
				return true
			}
		}
		return a.skip(page, cell, err)
	}

	if p.typ == 0x0a {
		for i := 0; i < p.ncell; i++ {
			if a.stop {
				return false
			}
			if err := p.checkCell(i); err != nil {
				if !a.skip(page, i, err) {
					return false
				}
				continue
			}
			c, err := parseIndexLeaf(p.data[p.cellOffset(i):], a.db.header.PageSize)
			if err != nil {
				if !a.skip(page, i, err) {
					return false
				}
				continue
			}
			if !record(c, i) {
				return false
			}
		}
		return true
	}

	for i := 0; i < p.ncell; i++ {
		if a.stop {
			return false
		}
		if err := p.checkCell(i); err != nil {
			if !a.skip(page, i, err) {
				return false
			}
			continue
		}
		c, err := parseIndexInterior(p.data[p.cellOffset(i):], a.db.header.PageSize)
		if err != nil {
			if !a.skip(page, i, err) {
				return false
			}
			continue
		}
		if !a.indexPage(c.left, depth-1) && !a.salvage {
			return false
		}
		// The interior cell also holds a record.
		if !record(c.payload, i) {
			return false
		}
	}
	return a.indexPage(p.interiorRightmost(), depth-1)
}

// payload completes a (possibly overflowed) cell payload. Unlike addOverflow
// it never panics: a short or looping overflow chain, or a payload length
// which does not match the data, is an error.
func (a *auditor) payload(page int, pl cellPayload) ([]byte, error) {
	if pl.Length < 0 {
		return nil, fmt.Errorf("negative payload length %d", pl.Length)
	}
	// pl.Payload is the payload as it sits in the page; for a payload which
	// fits entirely in the page it is the remainder of the page starting at
	// the cell payload offset, so it can be longer than pl.Length.
	out := make([]byte, 0, pl.Length)
	out = append(out, pl.Payload...)
	overflow := pl.Overflow
	seen := map[int]bool{}
	firstOverflow := true
	for int64(len(out)) < pl.Length {
		if overflow == 0 {
			return nil, fmt.Errorf("payload truncated: have %d of %d bytes", len(out), pl.Length)
		}
		if seen[overflow] {
			return nil, fmt.Errorf("overflow chain loops back to page %d", overflow)
		}
		seen[overflow] = true
		buf, err := a.db.page(overflow)
		if err != nil {
			return nil, fmt.Errorf("overflow page %d: %v", overflow, err)
		}
		if len(buf) < 4 {
			return nil, fmt.Errorf("overflow page %d too short", overflow)
		}
		next := int(binary.BigEndian.Uint32(buf[:4]))
		out = append(out, buf[4:]...)
		overflow = next
		firstOverflow = false
	}
	// The payload is complete, but a non-zero overflow pointer on the last
	// needed overflow page points at data which is not part of this cell.
	// sqlite3 reports that as damage; the record itself is still readable.
	if !firstOverflow && overflow != 0 {
		a.w.Warnings = append(a.w.Warnings, fmt.Sprintf(
			"page %d: overflow chain continues (next page %d) after the payload of %d bytes is complete",
			page, overflow, pl.Length))
	}
	return out[:pl.Length], nil
}

// MasterEntry is one sqlite_master row, decoded on its own. If the cell or
// record could not be decoded Err is set and the other fields are zero.
type MasterEntry struct {
	Type     string
	Name     string
	TblName  string
	RootPage int
	SQL      string
	Page     int
	Err      error
}

// MasterAudit is the result of reading sqlite_master cell by cell.
type MasterAudit struct {
	Entries []MasterEntry
	// Problems lists cells and pages of sqlite_master which could not be
	// decoded.
	Problems []AuditProblem
}

// Complete reports whether every cell of sqlite_master could be decoded.
func (m *MasterAudit) Complete() bool {
	return len(m.Problems) == 0
}

// AuditMaster reads sqlite_master without giving up on the whole table when a
// single cell is damaged: every decodable row is returned, and unusable cells
// are recorded in Problems. Only an unreadable page 1 results in an error.
func (db *Database) AuditMaster() (*MasterAudit, error) {
	if err := db.resolveDirty(); err != nil {
		return nil, err
	}
	p, err := db.auditPage(1)
	if err != nil {
		return nil, err
	}
	if p.typ != 0x0d && p.typ != 0x05 {
		return nil, fmt.Errorf("page 1 is not a sqlite_master table page (type 0x%02x)", p.typ)
	}
	ma := &MasterAudit{}
	a := &masterAuditor{db: db, m: ma, seen: map[int]bool{}}
	a.page(1, maxRecursion)
	return ma, nil
}

type masterAuditor struct {
	db   *Database
	m    *MasterAudit
	seen map[int]bool
}

func (a *masterAuditor) page(page, depth int) {
	if depth <= 0 {
		a.m.Problems = append(a.m.Problems, AuditProblem{Page: page, Cell: -1, Err: ErrRecursion})
		return
	}
	if a.seen[page] {
		a.m.Problems = append(a.m.Problems, AuditProblem{Page: page, Cell: -1, Err: errors.New("page is referenced more than once (btree loop)")})
		return
	}
	p, err := a.db.auditPage(page)
	if err != nil {
		a.m.Problems = append(a.m.Problems, AuditProblem{Page: page, Cell: -1, Err: err})
		return
	}
	if p.typ != 0x0d && p.typ != 0x05 {
		a.m.Problems = append(a.m.Problems, AuditProblem{Page: page, Cell: -1, Err: fmt.Errorf("expected a table page, found page type 0x%02x", p.typ)})
		return
	}
	a.seen[page] = true

	if p.typ == 0x0d {
		for i := 0; i < p.ncell; i++ {
			entry, err := a.cell(p, i)
			if err != nil {
				a.m.Problems = append(a.m.Problems, AuditProblem{Page: page, Cell: i, Err: err})
				continue
			}
			entry.Page = page
			a.m.Entries = append(a.m.Entries, entry)
		}
		return
	}
	for i := 0; i < p.ncell; i++ {
		if err := p.checkCell(i); err != nil {
			a.m.Problems = append(a.m.Problems, AuditProblem{Page: page, Cell: i, Err: err})
			continue
		}
		c, err := parseTableInterior(p.data[p.cellOffset(i):])
		if err != nil {
			a.m.Problems = append(a.m.Problems, AuditProblem{Page: page, Cell: i, Err: err})
			continue
		}
		a.page(c.left, depth-1)
	}
	a.page(p.interiorRightmost(), depth-1)
}

func (a *masterAuditor) cell(p *auditPage, i int) (MasterEntry, error) {
	if err := p.checkCell(i); err != nil {
		return MasterEntry{}, err
	}
	c, err := parseTableLeaf(p.data[p.cellOffset(i):], a.db.header.PageSize)
	if err != nil {
		return MasterEntry{}, err
	}
	full, err := (&auditor{db: a.db}).payload(p.pageNo(), c.payload)
	if err != nil {
		return MasterEntry{}, err
	}
	rec, err := parseRecord(full)
	if err != nil {
		return MasterEntry{}, err
	}
	return masterEntry(rec)
}

func masterEntry(rec Record) (MasterEntry, error) {
	if len(rec) != 5 {
		return MasterEntry{}, fmt.Errorf("not a sqlite_master record: %d fields", len(rec))
	}
	var e MasterEntry
	s, ok := rec[0].(string)
	if !ok {
		return e, errors.New("invalid sqlite_master record: type is not text")
	}
	e.Type = s
	s, ok = rec[1].(string)
	if !ok {
		return e, errors.New("invalid sqlite_master record: name is not text")
	}
	e.Name = s
	s, ok = rec[2].(string)
	if !ok {
		return e, errors.New("invalid sqlite_master record: tbl_name is not text")
	}
	e.TblName = s
	n, ok := rec[3].(int64)
	if !ok {
		return e, errors.New("invalid sqlite_master record: rootpage is not an integer")
	}
	e.RootPage = int(n)
	switch s := rec[4].(type) {
	case string:
		e.SQL = s
	case nil:
	default:
		return e, errors.New("invalid sqlite_master record: sql is not text")
	}
	return e, nil
}
