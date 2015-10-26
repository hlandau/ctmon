package ctclient

import denet "github.com/hlandau/degoutils/net"
import "net/http"
import "sync"
import "time"
import "encoding/json"
import "fmt"
import "strings"
import "github.com/hlandau/xlog"
import "encoding/binary"

var log, Log = xlog.New("ctclient")

type EntryType uint16

const (
	X509Entry EntryType = iota
	PrecertEntry
)

func (et EntryType) String() string {
	switch et {
	case X509Entry:
		return "x509Entry"
	case PrecertEntry:
		return "precertEntry"
	default:
		return "unknown"
	}
}

type Entry struct {
	Time time.Time
	Type EntryType

	Index int64

	// Either a proper certificate or a signed & poisoned precertificate.
	LeafCertificate  []byte
	CertificateChain [][]byte

	// This is the proper certificate or a TBSCertificate for precertificates.
	// Depends on EntryType.
	EntryCertificate []byte
	IssuerKeyHash    [32]byte // Precert entries only.

	Extensions []byte
}

type Client struct {
	Client *http.Client
	LogURL string

	initOnce sync.Once
}

func (c *Client) init() {
	c.initOnce.Do(func() {
		if c.Client == nil {
			c.Client = http.DefaultClient
		}
		c.LogURL = strings.TrimSuffix(c.LogURL, "/")
	})
}

// numEntries includes any entries which could not be parsed, which are not included in entries.
func (c *Client) GetEntries(start, end int64) (entries []*Entry, numEntries int, err error) {
	c.init()

	u := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", c.LogURL, start, end)
	res, err := denet.Require200(c.Client.Get(u))
	if err != nil {
		return nil, 0, err
	}

	defer res.Body.Close()

	var ger getEntriesResponse
	err = json.NewDecoder(res.Body).Decode(&ger)
	if err != nil {
		return nil, 0, err
	}

	for i, e := range ger.Entries {
		ee, err := decodeEntry(e)
		if err == nil {
			ee.Index = int64(i) + start
			entries = append(entries, ee)
		} else {
			log.Errorf("unknown entry in log %#v: %v", c.LogURL, err)
		}
	}

	return entries, len(ger.Entries), nil
}

func decodeEntry(e *entry) (*Entry, error) {
	ee := &Entry{}

	err := decodeEntryLeaf(ee, e)
	if err != nil {
		return nil, err
	}

	switch ee.Type {
	case X509Entry:
		err = decodeEntryCerts(ee, e, false)
	case PrecertEntry:
		err = decodeEntryCerts(ee, e, true)
	}
	if err != nil {
		return nil, err
	}

	return ee, nil
}

func decodeEntryCerts(ee *Entry, e *entry, precert bool) error {
	b := e.ExtraData

	if precert {
		// Read the precertificate.
		if len(b) < 3 {
			return fmt.Errorf("undersize buffer")
		}

		L := (int(b[0]) << 16) | (int(b[1]) << 8) | int(b[2])
		b = b[3:]
		if len(b) < (L + 3) {
			return fmt.Errorf("malformed data (ed1) %v %v", len(b), L)
		}

		b = b[3:]
		ee.LeafCertificate = b[0:L]

		b = b[L:]
	}

	if len(b) < 3 {
		return fmt.Errorf("undersize buffer (2)")
	}

	var extraCertificates [][]byte
	L := (int(b[0]) << 16) | (int(b[1]) << 8) | int(b[2])
	b = b[3:3+L]
	for len(b) > 0 {
		if len(b) < 3 {
			return fmt.Errorf("malformed data (ed2)")
		}

		L := (int(b[0]) << 16) | (int(b[1]) << 8) | int(b[2])
		b = b[3:]

		if len(b) < L {
			return fmt.Errorf("malformed data (ed3) %v %v", len(b), L)
		}

		extraCertificates = append(extraCertificates, b[0:L])
		b = b[L:]
	}

	ee.CertificateChain = extraCertificates
	return nil
}

func decodeEntryLeaf(ee *Entry, e *entry) error {
	b := e.LeafInput
	if len(b) < 12 {
		return fmt.Errorf("undersize buffer")
	}

	// version, merkle leaf type
	if b[0] != 0 || b[1] != 0 /* timestamped entry */ {
		return fmt.Errorf("not suppported")
	}

	b = b[2:]

	// timestamp
	ts := binary.BigEndian.Uint64(b[0:8])
	b = b[8:]

	// entry type
	entryType := EntryType(binary.BigEndian.Uint16(b[0:2]))

	if entryType != X509Entry && entryType != PrecertEntry {
		return fmt.Errorf("unknown entry type")
	}

	b = b[2:]

	if entryType == PrecertEntry {
		if len(b) < 32 {
			return fmt.Errorf("malformed data (1)")
		}

		copy(ee.IssuerKeyHash[:], b[0:32])
		b = b[32:]
	}

	// leaf certificate / TBS certificate
	L := (int(b[0]) << 16) | (int(b[1]) << 8) | int(b[2])
	if len(b) < (L + 3 + 2) {
		return fmt.Errorf("malformed data (2)")
	}

	certificate := b[3 : 3+L]
	b = b[3+L:]

	// extensions
	L = int(binary.BigEndian.Uint16(b[0:2]))
	if len(b) < (L + 2) {
		return fmt.Errorf("malformed data (not enough room for extensions: %d bytes indicated, %d bytes remaining)", L, len(b)-2)
	}

	extensions := b[2 : 2+L]
	b = b[2+L:]

	ee.Time = time.Unix(int64(ts/1000), int64((ts%1000)*1000000))
	ee.Type = entryType
	if ee.Type == X509Entry {
		ee.LeafCertificate = certificate
	}
	ee.Extensions = extensions
	return nil
}

// structs used for decoding

type getEntriesResponse struct {
	Entries []*entry `json:"entries"`
}

type entry struct {
	LeafInput denet.Base64 `json:"leaf_input"`
	ExtraData denet.Base64 `json:"extra_data"`
}
