package server

import "github.com/hlandau/xlog"
import denet "github.com/hlandau/degoutils/net"
import "github.com/hlandau/ctmon/ctclient"
import "crypto/x509"
import "fmt"
import "sync"
import "sync/atomic"
import "github.com/willf/bloom"
//import "github.com/hlandau/degoutils/dbutil"
import "text/template"
import htmltemplate "html/template"
import "time"

//import "github.com/hlandau/degoutils/sendemail"
import "crypto/sha256"

//import "github.com/jackc/pgx"

import "database/sql"
import "github.com/lib/pq"

var log, Log = xlog.New("ctmon.server")

type Config struct {
	DBURI string `default:"" usage:"PostgreSQL DB URI"`
}

type Server struct {
	cfg                Config
	stopping           int32
	stopWait           sync.WaitGroup
  stopChan chan struct{}
  stopOnce sync.Once
	bloomFilter        *bloom.BloomFilter
	//dbpool             *pgx.ConnPool
	dbpool             *sql.DB
	textNotifyEmailTpl *template.Template
	htmlNotifyEmailTpl *htmltemplate.Template
  prepareds          prepareds
}

func New(cfg Config) (*Server, error) {
	s := &Server{
		cfg: cfg,
    stopChan: make(chan struct{}),
	}

	//s.textNotifyEmailTpl = template.Must(template.New("text-notify-email").Parse(textNotifyEmailSrc))
	//s.htmlNotifyEmailTpl = htmltemplate.Must(htmltemplate.New("html-notify-email").Parse(htmlNotifyEmailSrc))

	var err error
  s.dbpool, err = sql.Open("postgres", s.cfg.DBURI)
	//s.dbpool, err = dbutil.NewPgxPool(s.cfg.DBURI)
	if err != nil {
		return nil, err
	}

  log.Debug("preparing...")
  err = s.prepareds.Prepare(s.dbpool)
  if err != nil {
    return nil, err
  }

  log.Debug("loading hostname bloom filter...")
	err = s.loadHostnameBloomFilter()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) loadHostnameBloomFilter() error {
	s.bloomFilter = bloom.New(256*1024*8, 2)

	rows, err := s.dbpool.Query("SELECT hostname FROM hostname_watch")
	if err != nil {
		return err
	}

	defer rows.Close()
	for rows.Next() {
		var hostname string
		err := rows.Scan(&hostname)
		if err != nil {
			return err
		}

		s.bloomFilter.AddString(hostname)
	}

	return nil
}

func (s *Server) Stop() error {
  s.stopOnce.Do(func() {
    atomic.StoreInt32(&s.stopping, 1)
    close(s.stopChan)
    s.stopWait.Wait()
  })
	return nil
}

type entryBatch struct {
	Entries    []*ctclient.Entry
	NumEntries int
	StartIndex int64
}

func (s *Server) Start() error {
	// Load certificate logs
	rows, err := s.dbpool.Query("SELECT id, url, current_height FROM certificate_log")
	if err != nil {
		return err
	}

	defer rows.Close()
	for rows.Next() {
		var id int64
		var url string
		var currentHeight int64
		err := rows.Scan(&id, &url, &currentHeight)
		if err != nil {
			return err
		}

		s.stopWait.Add(1)
		entryChan := make(chan entryBatch, 3)
		go s.logQueryLoop(id, url, currentHeight, entryChan)
		go s.logProcessLoop(id, entryChan)
	}

	return nil
}

func (s *Server) logQueryLoop(logID int64, logURL string, start int64, entryChan chan<- entryBatch) {
	defer close(entryChan)

	numPerQuery := int64(10000)
	backoff := denet.Backoff{}
	client := ctclient.Client{
		LogURL: logURL,
	}

  var sth *ctclient.STH
  ticker := time.NewTicker(2*time.Minute)
  defer ticker.Stop()
  oneTick := make(chan struct{}, 1)
  oneTick <- struct{}{}
  var err error

	for {
		if atomic.LoadInt32(&s.stopping) != 0 {
			break
		}

    if sth == nil {
      select {
      case <-ticker.C:
      case <-oneTick:
      case <-s.stopChan:
        continue
      }

      log.Debug("getting STH...")
      sth, err = client.GetSTH()
      if err != nil {
        log.Errore(err, "failed to get STH")
        backoff.Sleep()
        continue
      }
    }

    end := start + numPerQuery
    if end > sth.TreeSize {
      end = sth.TreeSize
    }
    if start >= end {
      log.Debugf("log %d: at the end", logID)
      sth = nil
      continue
    }

		log.Debugf("get entries: %#v: (%d,%d)", logURL, start, end-1)
		entries, numEntries, err := client.GetEntries(start, end-1)
		if err == nil {
			backoff.Reset()

			entryChan <- entryBatch{
				Entries:    entries,
				NumEntries: numEntries,
				StartIndex: start,
			}

			start += int64(numEntries)
			//err := s.processEntries(logID, entries, &start, numEntries)
			//log.Fatale(err, "update log height")
		} else {
			log.Errore(err, "cannot get entries for log: ", logURL)
			backoff.Sleep()
		}
	}

	log.Debugf("log reader stopped: %#v", logURL)
}

func (s *Server) logProcessLoop(logID int64, entryChan <-chan entryBatch) {
	defer s.stopWait.Done()

	for ei := range entryChan {
    log.Debugf("processing entries: log %d: (%d,%d)", logID, ei.StartIndex, ei.StartIndex+int64(ei.NumEntries)-1)

		err := s.processEntries(logID, ei.Entries, ei.StartIndex, ei.NumEntries)
		log.Fatale(err, "process entries")
	}
}

type hostnameQueueItem struct {
  CertificateID int64
  Hostname string
}

type observationQueueItem struct {
  CertificateID int64
  LogIndex int64
}

func (s *Server) processEntries(logID int64, entries []*ctclient.Entry, start int64, numEntries int) error {
	tx, err := s.dbpool.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

  txpr, err := s.prepareds.Tx(tx)
  if err != nil {
    return err
  }

  defer txpr.Close()

  var hnQueue []hostnameQueueItem
  observed := make([]observationQueueItem, 0, len(entries))

	for i, e := range entries {
		err := s.processEntry(logID, tx, txpr, &hnQueue, &observed, e, start+int64(i))
		log.Errore(err, "process entry")
	}

  chstmt, err := tx.Prepare(pq.CopyIn("certificate_hostname", "certificate_id", "hostname"))
  if err != nil {
    return err
  }

  defer chstmt.Close()

  log.Debugf("inserting %d hostnames", len(hnQueue))
  for i := range hnQueue {
    _, err = chstmt.Exec(hnQueue[i].CertificateID, hnQueue[i].Hostname)
    if err != nil {
      return err
    }
  }

  chstmt.Close()

  obstmt, err := tx.Prepare(pq.CopyIn("certificate_observation", "certificate_id", "log_id", "log_index"))
  if err != nil {
    return err
  }

  defer obstmt.Close()

  log.Debugf("inserting %d observations", len(observed))
  for i := range observed {
    _, err = obstmt.Exec(observed[i].CertificateID, logID, observed[i].LogIndex)
    if err != nil {
      return err
    }
  }

  obstmt.Close()

	_, err = tx.Exec("UPDATE certificate_log SET current_height=$1 WHERE id=$2", start+int64(numEntries), logID)
	if err != nil {
		return err
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	//*start = *start + int64(numEntries)
	return nil
}

func (s *Server) processEntry(logID int64, tx *sql.Tx, txpr *prepareds, hnQueue *[]hostnameQueueItem, observed *[]observationQueueItem, e *ctclient.Entry, logIndex int64) error {
	cert, err := x509.ParseCertificate(e.LeafCertificate)
	if err != nil {
		return fmt.Errorf("Failed to parse X.509 certificate: %v", err)
	}

	h := sha256.New()
	h.Write(e.LeafCertificate)
	certHash := h.Sum(nil)

	var certID int64
	var ncertID int64
	err = txpr.InsertCertificate.QueryRow(certHash, cert.NotBefore, cert.NotAfter).Scan(&certID, &ncertID)
	if err != nil {
		return err
	}

	wasInserted := certID == ncertID

	if wasInserted {
		hostnames := getCertificateHostnames(cert)
		for hostname := range hostnames {
      *hnQueue = append(*hnQueue, hostnameQueueItem{ certID, hostname, })
		}
	}

  *observed = append(*observed, observationQueueItem{
    CertificateID: certID,
    LogIndex: logIndex,
  })

  log.Debugf("log %d: entry %d", logID, logIndex)
	return nil
}

/*
func (s *Server) checkHostname(hostname string, e *ctclient.Entry, cert *x509.Certificate) error {
  log.Debug(hostname)

  for {
    err := s.checkHostnameSub(hostname, e, cert)
    if err != nil {
      return err
    }

    idx := strings.Index(hostname, ".")
    if idx < 0 {
      break
    }

    hostname = hostname[idx+1:]
  }

  return nil
}

func (s *Server) checkHostnameSub(hostname string, e *ctclient.Entry, cert *x509.Certificate) error {
  if !s.bloomFilter.TestString(hostname) {
    return nil
  }

  log.Debugf("  potential match: ", hostname)

  rows, err := s.dbpool.Query("SELECT id, notify_email FROM hostname_watch WHERE hostname=$1", hostname)
  if err != nil {
    return err
  }

  defer rows.Close()
  for rows.Next() {
    var id int64
    var notifyEmail pgx.NullString
    err := rows.Scan(&id, &notifyEmail)
    if err != nil {
      return err
    }

    if notifyEmail.String != "" {
      log.Debug("  confirmed -> %s", notifyEmail.String)
      s.sendNotificationEmail(notifyEmail.String, hostname, e, cert)
    }
  }

  return nil
}

const textNotifyEmailSrc = `Greetings.

You are receiving this e. mail because you previously requested notification of any certificate issued for the domain name {{.hostname}}.

A certificate has been logged with the following details:

Domain Name of Interest:  {{.hostname}}
Log Timestamp:            {{.time}}

Subject:                  {{.subject}}
Issuer:                   {{.issuer}}
Serial Number:            {{.serialNumber}}

Full List of Certificate Domain Names:
{{range .allHostnames}}
  {{.}}
{{end}}

For more information, you can see a list of certificates issued for {{.hostname}} at ctwatch:
  <http://api.ctwatch.net/domain/{{.hostname}}>

---
To stop receiving certificate transparency notifications, visit:
  <{{.unsubscribeURL}}>

`
const htmlNotifyEmailSrc = ``

func (s *Server) sendNotificationEmail(email, hostname string, e *ctclient.Entry, cert *x509.Certificate) {
  var textBuf bytes.Buffer
  var htmlBuf bytes.Buffer

  args := map[string]interface{}{
    "hostname": hostname,
    "email": email,
    "cert": cert,
    "time": e.Time,
    "subject": nameString(&cert.Subject),
    "issuer": nameString(&cert.Issuer),
    "serialNumber": cert.SerialNumber.String(),
    "allHostnames": getCertificateHostnames(cert),
    "unsubscribeURL": "TODO",
  }

  err := s.textNotifyEmailTpl.Execute(&textBuf, args)
  log.Warne(err, "Failed to execute text notification e. mail template")

  s.htmlNotifyEmailTpl.Execute(&htmlBuf, args)
  log.Warne(err, "Failed to execute HTML notification e. mail template")

  em := &sendemail.Email{
    To: []string{ email, },
    TextBody: textBuf.String(),
    HTMLBody: htmlBuf.String(),
  }
  sendemail.SendAsync(em)
}*/
