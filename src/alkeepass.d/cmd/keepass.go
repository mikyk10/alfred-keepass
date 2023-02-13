package cmd

import (
	"io"

	"github.com/pkg/errors"
	"github.com/tobischo/gokeepasslib/v3"
)

func openKbdx(rd io.Reader, credentials *gokeepasslib.DBCredentials) (*gokeepasslib.Database, error) {

	db := gokeepasslib.NewDatabase()
	db.Credentials = credentials

	err := gokeepasslib.NewDecoder(rd).Decode(db)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	err = db.UnlockProtectedEntries()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return db, nil
}
