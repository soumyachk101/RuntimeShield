package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSQLiteStoreAppliesSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rs.db")
	st, err := NewStore("sqlite", "", path)
	require.NoError(t, err, "open sqlite store")
	defer st.Close()
	require.NoError(t, st.ApplySchema(), "apply schema")
	require.NoError(t, st.Ping(), "ping")
	require.Equal(t, "sqlite", st.Backend())

	// A table from the migration must exist and accept a row.
	db := st.DB()
	_, err = db.Exec(
		`INSERT INTO organizations (id, name, plan, created_at) VALUES ('org1','Acme','community','2026-01-01T00:00:00Z')`,
	)
	require.NoError(t, err)
	var n int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM organizations`).Scan(&n))
	require.Equal(t, 1, n)
}

func TestPlaceholdersRewriteForPostgres(t *testing.T) {
	got := rewritePlaceholders(`SELECT ? FROM t WHERE x = ? AND y = ?`)
	want := `SELECT $1 FROM t WHERE x = $2 AND y = $3`
	require.Equal(t, want, got)
}

func TestUnknownBackendRejected(t *testing.T) {
	_, err := NewStore("mysql", "", "")
	require.Error(t, err)
}
