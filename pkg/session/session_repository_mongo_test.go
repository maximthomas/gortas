//go:build integration
// +build integration

package session

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/maximthomas/gortas/pkg/models"
	"github.com/stretchr/testify/assert"
)

const testSessionID = "c48abbfc-93f9-46d6-b568-5a9d8394a156"

func TestGetSession(t *testing.T) {

	repo := getRepo(t, true)
	t.Run("test get session", func(t *testing.T) {
		sess, err := repo.GetSession(testSessionID)
		assert.NoError(t, err)
		assert.Equal(t, testSessionID, sess.ID)
	})
	t.Run("test get not existing session", func(t *testing.T) {
		sess, err := repo.GetSession("bad")
		assert.Error(t, err)
		assert.Empty(t, sess.ID)
	})
}

func TestCreateSession(t *testing.T) {
	getRepo(t, true)
	repo := getRepo(t, false)
	t.Run("test create session", func(t *testing.T) {
		session := models.Session{
			Properties: map[string]string{
				"prop1": "value",
			},
		}
		newSession, err := repo.CreateSession(session)
		assert.NoError(t, err)
		assert.NotEmpty(t, newSession.ID)
	})
}

func TestDeleteSession(t *testing.T) {
	repo := getRepo(t, true)
	t.Run("test delete session", func(t *testing.T) {
		_, err := repo.GetSession(testSessionID)
		assert.NoError(t, err)

		err = repo.DeleteSession(testSessionID)
		assert.NoError(t, err)

		_, err = repo.GetSession(testSessionID)
		assert.Error(t, err)

	})
}

func TestUpdateSession(t *testing.T) {
	repo := getRepo(t, true)
	t.Run("test update session", func(t *testing.T) {
		sess, err := repo.GetSession(testSessionID)
		assert.NoError(t, err)
		assert.Equal(t, testSessionID, sess.ID)
		(&sess).Properties["prop2"] = "value2"
		err = repo.UpdateSession(sess)
		assert.NoError(t, err)
		newSess, _ := repo.GetSession(testSessionID)
		assert.Equal(t, sess.Properties["prop2"], newSess.Properties["prop2"])

	})
	t.Run("test get not existing session", func(t *testing.T) {
		err := repo.UpdateSession(models.Session{
			ID:         "bad",
			Properties: nil,
		})
		assert.Error(t, err)
	})
}

func TestGepRepoMultipleTimes(t *testing.T) {
	_, err := NewMongoSessionRepository("mongodb://root:changeme@localhost:27017", "test_sessions", "sessions")
	assert.NoError(t, err)

	_, err = NewMongoSessionRepository("mongodb://root:changeme@localhost:27017", "test_sessions", "sessions")
	assert.NoError(t, err)
}

func getRepo(t *testing.T, drop bool) SessionRepository {
	repo, err := NewMongoSessionRepository("mongodb://root:changeme@localhost:27017", "test_sessions", "sessions")
	assert.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if drop {
		err = repo.client.Database(repo.db).Drop(ctx)
		assert.NoError(t, err)
	}
	session := models.Session{
		ID: testSessionID,
		Properties: map[string]string{
			"prop1": "value",
		},
	}
	_, err = repo.CreateSession(session)
	assert.NoError(t, err)

	return repo
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func startDockerCompose() {
	dir, err := os.Getwd()
	checkErr(err)
	cmd := exec.Command("docker-compose", "-f", "docker-compose-mongodb-ldap.yaml", "--project-directory", dir, "up", "-d")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	checkErr(err)
}

func stopDockerCompose() {
	dir, err := os.Getwd()
	checkErr(err)
	cmd := exec.Command("docker-compose", "-f", "docker-compose-mongodb-ldap.yaml", "--project-directory", dir, "down")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	checkErr(err)
}
