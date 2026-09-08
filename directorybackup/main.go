package main

import (
	"clientcommon"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"pbscommon"
	"runtime"
	"snapshot"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/tawesoft/golib/v2/dialog"
)

var defaultMailSubjectTemplate = "Backup {{.Status}}"
var defaultMailBodyTemplate = `{{if .Success}}Backup complete ({{.FromattedDuration}})
Chunks New {{.NewChunks}}, Reused {{.ReusedChunks}}.{{else if .Partial}}Backup completed WITH ERRORS ({{.FromattedDuration}})
{{.ReadErrorCount}} file(s) could not be read and were skipped; the snapshot is incomplete.
Chunks New {{.NewChunks}}, Reused {{.ReusedChunks}}.{{else}}Error occurred while working, backup may be not completed.
Last error is: {{.ErrorStr}}{{end}}`

type ChunkState struct {
	assignments        []string
	assignments_offset []uint64
	pos                uint64
	wrid               uint64
	chunkcount         uint64
	chunkdigests       hash.Hash
	current_chunk      []byte
	C                  pbscommon.Chunker
	newchunk           *atomic.Uint64
	reusechunk         *atomic.Uint64
	knownChunks        *haxmap.Map[string, bool]

	// recording captures the chunks emitted between BeginRecord and EndRecord, so
	// a file's payload span can be recorded for next-run reuse.
	recording bool
	recorded  []pbscommon.ReusedChunk
}

func (c *ChunkState) Init(newchunk *atomic.Uint64, reusechunk *atomic.Uint64, knownChunks *haxmap.Map[string, bool]) {
	c.assignments = make([]string, 0)
	c.assignments_offset = make([]uint64, 0)
	c.pos = 0
	c.chunkcount = 0
	c.chunkdigests = sha256.New()
	c.current_chunk = make([]byte, 0)
	c.C = pbscommon.Chunker{}
	c.C.New(1024 * 1024 * 4)
	c.reusechunk = reusechunk
	c.newchunk = newchunk
	c.knownChunks = knownChunks
}

// emitCurrentChunk finalizes the pending chunk: compute its (key-scoped) digest,
// upload it if new, register it in the dynamic index at the current offset, and
// (when recording) note it for reuse. No-op if the buffer is empty.
func (c *ChunkState) emitCurrentChunk(client *pbscommon.PBSClient) error {
	if len(c.current_chunk) == 0 {
		return nil
	}
	bindigest := client.ChunkDigest(c.current_chunk)
	shahash := hex.EncodeToString(bindigest[:])
	length := uint64(len(c.current_chunk))

	if _, ok := c.knownChunks.GetOrSet(shahash, true); !ok {
		c.newchunk.Add(1)
		if err := client.UploadDynamicCompressedChunk(c.wrid, shahash, c.current_chunk); err != nil {
			return fmt.Errorf("failed to upload chunk %s: %w", shahash, err)
		}
	} else {
		c.reusechunk.Add(1)
	}

	if err := binary.Write(c.chunkdigests, binary.LittleEndian, c.pos+length); err != nil {
		return fmt.Errorf("failed to write chunk offset: %w", err)
	}
	if _, err := c.chunkdigests.Write(bindigest[:]); err != nil {
		return fmt.Errorf("failed to write chunk digest: %w", err)
	}
	c.assignments_offset = append(c.assignments_offset, c.pos)
	c.assignments = append(c.assignments, shahash)
	if c.recording {
		c.recorded = append(c.recorded, pbscommon.ReusedChunk{Digest: shahash, Length: length})
	}
	c.pos += length
	c.chunkcount++
	c.current_chunk = make([]byte, 0)
	return nil
}

// Break finalizes any pending chunk and resets the content-defined chunker, so
// the next bytes start a fresh chunk. This aligns a file's payload span to chunk
// boundaries — required so the span is whole chunks that can be recorded and,
// next run, referenced without re-reading. Deterministic: the same file content
// after a Break always produces the same chunks.
func (c *ChunkState) Break(client *pbscommon.PBSClient) error {
	if err := c.emitCurrentChunk(client); err != nil {
		return err
	}
	c.C = pbscommon.Chunker{}
	c.C.New(1024 * 1024 * 4)
	return nil
}

// BeginRecord/EndRecord bracket a file span whose emitted chunks should be
// captured for next-run reuse.
func (c *ChunkState) BeginRecord() {
	c.recording = true
	c.recorded = nil
}

func (c *ChunkState) EndRecord() []pbscommon.ReusedChunk {
	c.recording = false
	out := c.recorded
	c.recorded = nil
	return out
}

// AssignKnown references already-existing chunks (from a previous backup) in the
// dynamic index at the current position, without uploading data — this is how an
// unchanged file's payload is reused. The caller must have Broken first so the
// index position is chunk-aligned. Advances pos by the chunks' total length.
func (c *ChunkState) AssignKnown(chunks []pbscommon.ReusedChunk) error {
	if len(c.current_chunk) != 0 {
		return fmt.Errorf("AssignKnown called with %d unflushed bytes (missing Break)", len(c.current_chunk))
	}
	for _, ch := range chunks {
		raw, err := hex.DecodeString(ch.Digest)
		if err != nil || len(raw) != 32 {
			return fmt.Errorf("invalid reused chunk digest %q", ch.Digest)
		}
		if err := binary.Write(c.chunkdigests, binary.LittleEndian, c.pos+ch.Length); err != nil {
			return err
		}
		if _, err := c.chunkdigests.Write(raw); err != nil {
			return err
		}
		c.assignments_offset = append(c.assignments_offset, c.pos)
		c.assignments = append(c.assignments, ch.Digest)
		c.knownChunks.Set(ch.Digest, true)
		c.reusechunk.Add(1)
		c.pos += ch.Length
		c.chunkcount++
		if c.recording {
			c.recorded = append(c.recorded, ch)
		}
	}
	return nil
}

func (c *ChunkState) HandleData(b []byte, client *pbscommon.PBSClient) error {
	chunkpos := c.C.Scan(b)

	if chunkpos == 0 {
		//No break happened, just append data
		c.current_chunk = append(c.current_chunk, b...)
	} else {

		for chunkpos > 0 {
			//Append data until break position
			c.current_chunk = append(c.current_chunk, b[:chunkpos]...)

			if err := c.emitCurrentChunk(client); err != nil {
				return err
			}

			b = b[chunkpos:] //Take remainder of data
			chunkpos = c.C.Scan(b)

		}

		//No further break happened, append remaining data
		c.current_chunk = append(c.current_chunk, b...)
	}
	return nil
}

func (c *ChunkState) Eof(client *pbscommon.PBSClient) error {
	//Here we write the remainder of data for which cyclic hash did not trigger

	if err := c.emitCurrentChunk(client); err != nil {
		return err
	}
	//Avoid incurring in request entity too large by chunking assignment PUT requests in blocks of at most 128 chunks
	for k := 0; k < len(c.assignments); k += 128 {
		k2 := k + 128
		if k2 > len(c.assignments) {
			k2 = len(c.assignments)
		}
		if err := client.AssignDynamicChunks(c.wrid, c.assignments[k:k2], c.assignments_offset[k:k2]); err != nil {
			return fmt.Errorf("failed to assign chunks (batch %d-%d): %w", k, k2, err)
		}
	}

	if err := client.CloseDynamicIndex(c.wrid, hex.EncodeToString(c.chunkdigests.Sum(nil)), c.pos, c.chunkcount); err != nil {
		return fmt.Errorf("failed to close dynamic index: %w", err)
	}
	return nil
}

func main() {
	var newchunk *atomic.Uint64 = new(atomic.Uint64)
	var reusechunk *atomic.Uint64 = new(atomic.Uint64)

	cfg := loadConfig()

	if ok := cfg.valid(); !ok {
		if runtime.GOOS == "windows" {
			usage := "All options are mandatory:\n"
			flag.VisitAll(func(f *flag.Flag) {
				usage += "-" + f.Name + " " + f.Usage + "\n"
			})
			dialog.Error(usage)
		} else {
			fmt.Println("All options are mandatory")

			flag.PrintDefaults()
		}
		os.Exit(1)
	}

	L := clientcommon.Locking{}

	lock_ok := L.AcquireProcessLock()
	if !lock_ok {

		dialog.Error("Backup jobs need to run exclusively, please wait until the previous job has finished")
		os.Exit(2)
	}
	defer L.ReleaseProcessLock()

	insecure := cfg.CertFingerprint != ""

	client := &pbscommon.PBSClient{
		BaseURL:         cfg.BaseURL,
		CertFingerPrint: cfg.CertFingerprint, //"ea:7d:06:f9:87:73:a4:72:d0:e8:05:a4:b3:3d:95:d7:0a:26:dd:6d:5c:ca:e6:99:83:e4:11:3b:5f:10:f4:4b",
		AuthID:          cfg.AuthID,
		Secret:          cfg.Secret,
		Username:        cfg.PBSUsername,
		Password:        cfg.PBSPassword,
		Datastore:       cfg.Datastore,
		Namespace:       cfg.Namespace,
		Insecure:        insecure,
		Manifest: pbscommon.BackupManifest{
			BackupID: cfg.BackupID,
		},
	}
	if client.Username != "" {
		if err := client.ObtainTicket(); err != nil {
			fmt.Printf("Error: ticket login failed: %v\n", err)
			os.Exit(1)
		}
	}
	if cfg.Keyfile != "" {
		crypt, err := pbscommon.LoadCryptConfigFromKeyfile(cfg.Keyfile)
		if err != nil {
			fmt.Printf("Error: loading encryption keyfile: %v\n", err)
			os.Exit(1)
		}
		client.Crypt = crypt
		fp := crypt.Fingerprint()
		fmt.Printf("Client-side encryption ENABLED (AES-256-GCM), key fingerprint %x\n", fp[:])
	}
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Failed to retrieve hostname:", err)
		hostname = "unknown"
	}

	begin := time.Now()
	var readErrors []string
	if len(cfg.Archives) > 0 {
		readErrors, err = backup_multi(client, newchunk, reusechunk, cfg.Archives, cfg.UseVSS)
	} else if cfg.BackupSourceDir != "" {
		readErrors, err = backup(client, newchunk, reusechunk, cfg.PxarOut, cfg.BackupSourceDir, cfg.UseVSS, cfg.Split, cfg.StatePath, cfg.SeedSnapshot, cfg.SeedArchives)
	} else if cfg.BackupStreamName != "" {
		sn := cfg.BackupStreamName
		if !strings.HasSuffix(sn, ".didx") {
			sn += ".didx"
		}
		fmt.Printf("Backing up from STDIN to %s", sn)
		err = backup_stream(client, newchunk, reusechunk, sn, os.Stdin)

	} else {
		panic("No backup dir or stream name specified, exiting")
	}

	end := time.Now()

	mailCtx := clientcommon.MailCtx{
		NewChunks:    newchunk.Load(),
		ReusedChunks: reusechunk.Load(),
		Error:        err,
		ReadErrors:   readErrors,
		Hostname:     hostname,
		Datastore:    cfg.Datastore,
		StartTime:    begin,
		EndTime:      end,
	}

	mailBodyTemplate := defaultMailBodyTemplate
	if cfg.SMTP != nil && cfg.SMTP.Template != nil && cfg.SMTP.Template.Body != "" {
		mailBodyTemplate = cfg.SMTP.Template.Body
	}

	fmt.Printf("New %d, Reused %d, backup took %s.\n", newchunk.Load(), reusechunk.Load(), end.Sub(begin))
	var msg string
	msg, err = mailCtx.BuildStr(mailBodyTemplate)
	if err != nil {
		fmt.Println("Cannot use custom mail body: " + err.Error())
		msg, err = mailCtx.BuildStr(defaultMailBodyTemplate)
		if err != nil {
			// this should never happen
			panic(err)
		}
	}

	if cfg.SMTP != nil {
		var subject string

		mailSubjectTemplate := defaultMailSubjectTemplate
		if cfg.SMTP.Template != nil && cfg.SMTP.Template.Subject != "" {
			mailSubjectTemplate = cfg.SMTP.Template.Subject
		}

		subject, err = mailCtx.BuildStr(mailSubjectTemplate)
		if err != nil {
			fmt.Println("Cannot use custom mail subject: " + err.Error())
			subject, err = mailCtx.BuildStr(defaultMailSubjectTemplate)
			if err != nil {
				// this should never happen
				panic(err)
			}
		}
		client, err := clientcommon.SetupMailClient(cfg.SMTP.Host, cfg.SMTP.Port, cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.Insecure)
		if err != nil {
			fmt.Println("Cannot connect to mail server: " + err.Error())
			os.Exit(1)
		}
		defer client.Quit()
		for _, ccc := range cfg.SMTP.Mails {
			err = clientcommon.SendMail(ccc.From, ccc.To, subject, msg, client)
			if err != nil {
				fmt.Println("Cannot send email: " + err.Error())
				os.Exit(1)
			}
		}
	}

	// Exit non-zero so schedulers never read a failed or incomplete backup as
	// success. mailCtx.Error is the fatal error; ReadErrors means the snapshot
	// committed but is missing unreadable files.
	if mailCtx.Error != nil {
		fmt.Fprintln(os.Stderr, "backup failed:", mailCtx.Error)
		os.Exit(1)
	}
	if len(readErrors) > 0 {
		fmt.Fprintf(os.Stderr, "backup completed with %d read error(s); snapshot is incomplete\n", len(readErrors))
		os.Exit(3)
	}

}

func backup_stream(client *pbscommon.PBSClient, newchunk, reusechunk *atomic.Uint64, filename string, stream io.Reader) error {
	knownChunks := haxmap.New[string, bool]()
	client.Connect(false, "host")
	previousDidx, err := client.DownloadPreviousToBytes(filename)
	if err != nil {
		return err
	}

	fmt.Printf("Downloaded previous DIDX: %d bytes\n", len(previousDidx))

	// Defensive parse: a truncated/short/odd-length previous index (or a sub-8-byte
	// error body) must not panic — fall back to no dedup (re-upload everything).
	prevDigests := pbscommon.ParsePreviousDIDXChunkDigests(previousDidx)
	if len(prevDigests) == 0 {
		fmt.Printf("Previous index unusable or empty (%d bytes), uploading all chunks\n", len(previousDidx))
	}
	for _, shahash := range prevDigests {
		knownChunks.Set(shahash, true)
	}

	fmt.Printf("Known chunks: %d!\n", knownChunks.Len())

	streamChunk := ChunkState{}
	streamChunk.Init(newchunk, reusechunk, knownChunks)

	streamChunk.wrid, err = client.CreateDynamicIndex(filename)
	if err != nil {
		return err
	}
	B := make([]byte, 65536)
	for {
		n, rerr := stream.Read(B)

		b := B[:n]

		if err := streamChunk.HandleData(b, client); err != nil {
			return fmt.Errorf("failed to handle stream data: %w", err)
		}

		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			return fmt.Errorf("failed to read stream: %w", rerr)
		}
	}

	// Eof() already closes the dynamic index; closing it again fails the request
	// and aborts the snapshot before UploadManifest/Finish.
	if err := streamChunk.Eof(client); err != nil {
		return fmt.Errorf("failed to finalize stream: %w", err)
	}

	err = client.UploadManifest()
	if err != nil {
		return err
	}

	return client.Finish()
}

// backup_real_split runs a format-v2 (split-archive) backup: metadata to
// <base>.mpxar.didx, file payloads to <base>.ppxar.didx. Chunk dedup against the
// previous snapshot's indexes avoids re-uploading unchanged data. With a state
// file, PayloadReuse additionally skips re-READING unchanged files (see
// reuse_state.go).
// seedKnownChunks opens a reader session to an existing snapshot and loads the
// chunk digests of the given archive indexes into knownChunks, so a subsequent
// content-defined backup references those chunks instead of re-uploading them.
// This is what lets a fresh agent backup dedup against the existing pull backup
// (verified: the Go and Rust chunkers produce identical boundaries).
// snapshot is "type/id/ts" e.g. "host/win7/2026-09-02T18:52:10Z".
func seedKnownChunks(client *pbscommon.PBSClient, snapshot, archivesCsv string, knownChunks *haxmap.Map[string, bool]) (int, error) {
	parts := strings.Split(snapshot, "/")
	if len(parts) != 3 {
		return 0, fmt.Errorf("bad -seed-snapshot %q (want type/id/ts)", snapshot)
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", parts[2])
	if err != nil {
		return 0, fmt.Errorf("bad seed timestamp %q: %w", parts[2], err)
	}
	// A SEPARATE reader client, so the backup client's session/state is untouched.
	rc := &pbscommon.PBSClient{
		BaseURL: client.BaseURL, CertFingerPrint: client.CertFingerPrint,
		AuthID: client.AuthID, Secret: client.Secret,
		Username: client.Username, Password: client.Password,
		Ticket: client.Ticket, CSRFToken: client.CSRFToken,
		Datastore: client.Datastore, Namespace: client.Namespace,
		Insecure: client.Insecure,
	}
	rc.Manifest.BackupType, rc.Manifest.BackupID, rc.Manifest.BackupTime = parts[0], parts[1], t.Unix()
	rc.Connect(true, parts[0]) // reader session on the seed snapshot
	defer rc.Close()
	total := 0
	for _, a := range strings.Split(archivesCsv, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		data, err := rc.DownloadToBytes(a)
		if err != nil {
			return total, fmt.Errorf("seed download %s: %w", a, err)
		}
		for _, d := range pbscommon.ParsePreviousDIDXChunkDigests(data) {
			if _, existed := knownChunks.GetOrSet(d, true); !existed {
				total++
			}
		}
	}
	return total, nil
}

func backup_real_split(client *pbscommon.PBSClient, newchunk, reusechunk *atomic.Uint64, backupdir string, statePath, seedSnapshot, seedArchives string) ([]string, error) {
	knownChunks := haxmap.New[string, bool]()

	// Seed from an existing snapshot (e.g. the pull backup) over a reader session
	// BEFORE opening the backup session — a content-defined backup then references
	// those chunks instead of re-uploading them. Done first so it does not disturb
	// the writer connection.
	if seedSnapshot != "" && seedArchives != "" {
		n, err := seedKnownChunks(client, seedSnapshot, seedArchives, knownChunks)
		if err != nil {
			return nil, fmt.Errorf("seeding from %s: %w", seedSnapshot, err)
		}
		fmt.Printf("Seeded %d known chunks from %s [%s]\n", n, seedSnapshot, seedArchives)
	}

	client.Connect(false, "host")

	const mpxarName = "backup.mpxar.didx"
	const ppxarName = "backup.ppxar.didx"

	archive := &pbscommon.PXARArchive{}
	archive.Split = true
	archive.ArchiveName = mpxarName

	// Seed dedup from BOTH previous indexes so unchanged chunks are not re-uploaded.
	for _, name := range []string{mpxarName, ppxarName} {
		prev, err := client.DownloadPreviousToBytes(name)
		if err != nil {
			return nil, err
		}
		for _, d := range pbscommon.ParsePreviousDIDXChunkDigests(prev) {
			knownChunks.Set(d, true)
		}
	}
	fmt.Printf("Known chunks: %d\n", knownChunks.Len())

	mpxarChunk := ChunkState{}
	mpxarChunk.Init(newchunk, reusechunk, knownChunks)
	ppxarChunk := ChunkState{}
	ppxarChunk.Init(newchunk, reusechunk, knownChunks)

	var err error
	mpxarChunk.wrid, err = client.CreateDynamicIndex(mpxarName)
	if err != nil {
		return nil, err
	}
	ppxarChunk.wrid, err = client.CreateDynamicIndex(ppxarName)
	if err != nil {
		return nil, err
	}

	// Metadata reuse: files unchanged since the previous run (same size+mtime,
	// recorded in the local state) reference their payload chunks instead of being
	// re-read. Guarded so we only ever reference chunks the previous snapshot still
	// holds (seeded into knownChunks) — a stale state can cause a re-read, never a
	// dangling reference.
	// With -state: file-aligned chunking + skip-read reuse (best when READING is the
	// bottleneck — slow/remote source). Without -state: plain content-defined
	// chunking like the PBS/Rust client (best when UPLOAD is the bottleneck and the
	// data already exists in the datastore under a compatible chunking — dedups
	// against it, at the cost of re-reading locally, which is cheap on-machine).
	state := LoadReuseState(statePath)
	newState := NewReuseState()
	if statePath != "" {
		archive.ReuseThreshold = 1024 * 1024 // 1 MiB — below this, reading is cheap
		archive.Hooks = pbscommon.ReuseHooks{
			Break:       func() error { return ppxarChunk.Break(client) },
			BeginRecord: ppxarChunk.BeginRecord,
			EndRecord:   ppxarChunk.EndRecord,
			AssignKnown: ppxarChunk.AssignKnown,
		}
		archive.PayloadReuse = func(rel string, size, mtime uint64) ([]pbscommon.ReusedChunk, bool) {
			chunks, ok := state.Lookup(rel, size, mtime)
			if !ok {
				return nil, false
			}
			for _, ch := range chunks {
				if _, exists := knownChunks.Get(ch.Digest); !exists {
					return nil, false // previous snapshot no longer has it — re-read
				}
			}
			return chunks, true
		}
		archive.ReuseSink = func(rel string, size, mtime uint64, chunks []pbscommon.ReusedChunk) {
			newState.Record(rel, size, mtime, chunks)
		}
	}

	archive.WriteCB = func(b []byte) error { return mpxarChunk.HandleData(b, client) }
	archive.PayloadWriteCB = func(b []byte) error { return ppxarChunk.HandleData(b, client) }

	if _, err = archive.WriteDir(backupdir, "", true); err != nil {
		return nil, fmt.Errorf("failed to write directory archive: %w", err)
	}
	if err = archive.FinishSplit(); err != nil {
		return nil, err
	}

	if err = mpxarChunk.Eof(client); err != nil {
		return nil, err
	}
	if err = ppxarChunk.Eof(client); err != nil {
		return nil, err
	}
	if err = client.UploadManifest(); err != nil {
		return nil, err
	}

	reused, read := archive.ReuseStats()
	fmt.Printf("Split backup: %d files reused (not read), %d files read.\n", reused, read)
	if err := SaveReuseState(statePath, newState); err != nil {
		fmt.Printf("warning: could not save reuse state: %v\n", err)
	}
	return archive.ReadErrors, nil
}

// backup_multi_real backs up several directories as separate archive pairs
// (<name>.mpxar/<name>.ppxar) in ONE snapshot, content-defined. When the
// backup-id and archive names match an existing backup (the pull), each
// archive's own /previous registers those chunks server-side, so unchanged data
// is referenced instead of re-uploaded — this is how we reuse the pull's 850 GB.
func backup_multi_real(client *pbscommon.PBSClient, newchunk, reusechunk *atomic.Uint64, archives []ArchiveSpec) ([]string, error) {
	client.Connect(false, "host")
	knownChunks := haxmap.New[string, bool]()
	var readErrors []string

	for _, a := range archives {
		mpxar := a.Name + ".mpxar.didx"
		ppxar := a.Name + ".ppxar.didx"

		// Native per-archive /previous: downloads the previous snapshot's index
		// for THIS (backup-id, archive) AND registers those chunks in the server
		// session, so they can be referenced without re-upload.
		before := knownChunks.Len()
		for _, n := range []string{mpxar, ppxar} {
			prev, err := client.DownloadPreviousToBytes(n)
			if err != nil {
				return readErrors, fmt.Errorf("previous %s: %w", n, err)
			}
			for _, d := range pbscommon.ParsePreviousDIDXChunkDigests(prev) {
				knownChunks.Set(d, true)
			}
		}
		fmt.Printf("Archive %s: seeded %d known chunks from previous\n", a.Name, knownChunks.Len()-before)

		mp := ChunkState{}
		mp.Init(newchunk, reusechunk, knownChunks)
		pp := ChunkState{}
		pp.Init(newchunk, reusechunk, knownChunks)

		var err error
		if mp.wrid, err = client.CreateDynamicIndex(mpxar); err != nil {
			return readErrors, err
		}
		if pp.wrid, err = client.CreateDynamicIndex(ppxar); err != nil {
			return readErrors, err
		}

		archive := &pbscommon.PXARArchive{}
		archive.Split = true // content-defined (no reuse hooks) — matches the pull's chunking
		archive.ArchiveName = mpxar
		archive.WriteCB = func(b []byte) error { return mp.HandleData(b, client) }
		archive.PayloadWriteCB = func(b []byte) error { return pp.HandleData(b, client) }

		if _, err = archive.WriteDir(a.Dir, "", true); err != nil {
			return readErrors, fmt.Errorf("archive %s (%s): %w", a.Name, a.Dir, err)
		}
		if err = archive.FinishSplit(); err != nil {
			return readErrors, err
		}
		if err = mp.Eof(client); err != nil {
			return readErrors, err
		}
		if err = pp.Eof(client); err != nil {
			return readErrors, err
		}
		readErrors = append(readErrors, archive.ReadErrors...)
	}

	if err := client.UploadManifest(); err != nil {
		return readErrors, err
	}
	return readErrors, nil
}

// backup_multi wraps backup_multi_real with VSS (one shadow per source volume)
// and the final commit.
func backup_multi(client *pbscommon.PBSClient, newchunk, reusechunk *atomic.Uint64, archives []ArchiveSpec, usevss bool) ([]string, error) {
	var readErrors []string
	var err error
	if usevss {
		dirs := make([]string, len(archives))
		for i, a := range archives {
			dirs[i] = a.Dir
		}
		err = snapshot.CreateVSSSnapshot(dirs, func(snaps map[string]snapshot.SnapShot) error {
			remapped := make([]ArchiveSpec, len(archives))
			for i, a := range archives {
				remapped[i] = ArchiveSpec{Dir: remapToShadow(a.Dir, snaps), Name: a.Name}
			}
			var e error
			readErrors, e = backup_multi_real(client, newchunk, reusechunk, remapped)
			return e
		})
	} else {
		readErrors, err = backup_multi_real(client, newchunk, reusechunk, archives)
	}
	if err != nil {
		return readErrors, err
	}
	return readErrors, client.Finish()
}

// remapToShadow rewrites a source dir onto its VSS shadow copy. CreateVSSSnapshot
// keys the map by filepath.Abs(dir) with FullPath = the shadow path (on Linux the
// nop keeps FullPath == dir).
func remapToShadow(dir string, snaps map[string]snapshot.SnapShot) string {
	abs, _ := filepath.Abs(dir)
	if s, ok := snaps[abs]; ok && s.FullPath != "" {
		return s.FullPath
	}
	if s, ok := snaps[dir]; ok && s.FullPath != "" {
		return s.FullPath
	}
	return dir
}

func backup_real(client *pbscommon.PBSClient, newchunk, reusechunk *atomic.Uint64, pxarOut string, backupdir string, split bool, statePath, seedSnapshot, seedArchives string) ([]string, error) {
	if split {
		return backup_real_split(client, newchunk, reusechunk, backupdir, statePath, seedSnapshot, seedArchives)
	}
	client.Connect(false, "host")
	knownChunks := haxmap.New[string, bool]()

	archive := &pbscommon.PXARArchive{}
	archive.ArchiveName = "backup.pxar.didx"

	previousDidx, err := client.DownloadPreviousToBytes(archive.ArchiveName)
	if err != nil {
		return nil, err
	}

	fmt.Printf("Downloaded previous DIDX: %d bytes\n", len(previousDidx))

	/*f2, _ := os.Create("test.didx")
	defer f2.Close()

	f2.Write(previous_didx)*/

	/*
		Here we download the previous dynamic index to figure out which chunks are the same of what
		we are going to upload to avoid unnecessary traffic and compression cpu usage
	*/

	// Defensive parse: a truncated/short/odd-length previous index (or a sub-8-byte
	// error body) must not panic — fall back to no dedup (re-upload everything).
	prevDigests := pbscommon.ParsePreviousDIDXChunkDigests(previousDidx)
	if len(prevDigests) == 0 {
		fmt.Printf("Previous index unusable or empty (%d bytes), uploading all chunks\n", len(previousDidx))
	}
	for _, shahash := range prevDigests {
		knownChunks.Set(shahash, true)
	}

	fmt.Printf("Known chunks: %d!\n", knownChunks.Len())
	f := &os.File{}
	if pxarOut != "" {
		f, err = os.Create(pxarOut)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	/**/

	pxarChunk := ChunkState{}
	pxarChunk.Init(newchunk, reusechunk, knownChunks)

	pcat1Chunk := ChunkState{}
	pcat1Chunk.Init(newchunk, reusechunk, knownChunks)

	pxarChunk.wrid, err = client.CreateDynamicIndex(archive.ArchiveName)
	if err != nil {
		return nil, err
	}
	pcat1Chunk.wrid, err = client.CreateDynamicIndex("catalog.pcat1.didx")
	if err != nil {
		return nil, err
	}

	archive.WriteCB = func(b []byte) error {

		if pxarOut != "" {
			if _, err := f.Write(b); err != nil {
				return fmt.Errorf("failed to write to pxar output file: %w", err)
			}
		}

		if err := pxarChunk.HandleData(b, client); err != nil {
			return err
		}

		return nil
	}

	archive.CatalogWriteCB = func(b []byte) error {
		return pcat1Chunk.HandleData(b, client)
	}

	//This is the entry point of backup job which will start streaming with the PCAT and PXAR write callback
	//Data to be hashed and eventuall uploaded

	if _, err = archive.WriteDir(backupdir, "", true); err != nil {
		return nil, fmt.Errorf("failed to write directory archive: %w", err)
	}

	if err = pxarChunk.Eof(client); err != nil {
		return nil, err
	}
	if err = pcat1Chunk.Eof(client); err != nil {
		return nil, err
	}

	err = client.UploadManifest()
	if err != nil {
		return nil, err
	}
	// archive.ReadErrors lists files that could not be read and were skipped:
	// the snapshot committed but is incomplete. Surfaced as a partial result.
	return archive.ReadErrors, nil
}

func backup(client *pbscommon.PBSClient, newchunk, reusechunk *atomic.Uint64, pxarOut string, backupdir string, usevss bool, split bool, statePath, seedSnapshot, seedArchives string) ([]string, error) {

	fmt.Printf("Starting backup of %s\n", backupdir)
	var err error
	var readErrors []string
	if usevss {
		err = snapshot.CreateVSSSnapshot(([]string{backupdir}), func(snaps map[string]snapshot.SnapShot) error {
			// Get first snapshot from map (Go 1.22 compatible)
			for _, snap := range snaps {
				backupdir = snap.FullPath
				break
			}
			//Remove VSS snapshot on windows, on linux for now NOP
			var e error
			readErrors, e = backup_real(client, newchunk, reusechunk, pxarOut, backupdir, split, statePath, seedSnapshot, seedArchives)
			return e

		})
	} else {
		readErrors, err = backup_real(client, newchunk, reusechunk, pxarOut, backupdir, split, statePath, seedSnapshot, seedArchives)
	}

	if err != nil {
		return readErrors, err
	}

	// Commit the snapshot even on a partial (read-error) run so the data that
	// was readable is retained; the partial status is reported via readErrors.
	return readErrors, client.Finish()
}
