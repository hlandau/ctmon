package server

import "github.com/hlandau/degoutils/net/sqlprep"
import "database/sql"
import "reflect"

type prepareds struct {
  InsertCertificate *sql.Stmt `INSERT INTO certificate (certhash_sha256, t_valid_from, t_valid_until) VALUES ($1,$2,$3) ON CONFLICT ON CONSTRAINT u_certificate__certhash_sha256 DO UPDATE SET t_create=certificate.t_create RETURNING id, currval('certificate_id_seq')`
}

func (p *prepareds) Prepare(db *sql.DB) error {
	return sqlprep.Prepare(p, db)
}

func (p *prepareds) Close() error {
	return sqlprep.Close(p)
}

func (p *prepareds) Tx(tx *sql.Tx) (px *prepareds, err error) {
	px = &prepareds{}
	t := reflect.TypeOf(p).Elem()
	v := reflect.Indirect(reflect.ValueOf(p))
	v2 := reflect.Indirect(reflect.ValueOf(px))
	nf := t.NumField()
	for i := 0; i < nf; i++ {
		f := t.Field(i)
		if f.Tag == "" {
			continue
		}
		fv := v.Field(i)
		fv2 := v2.Field(i)
		fvi := fv.Interface()
		if fvi != nil {
			if stmt, ok := fvi.(*sql.Stmt); ok {
				fv2.Set(reflect.ValueOf(tx.Stmt(stmt)))
			}
		}
	}
	return
}
