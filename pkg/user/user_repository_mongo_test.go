//go:build integration
// +build integration

package user

import (
	"context"
	"github.com/google/uuid"
	"github.com/maximthomas/gortas/pkg/models"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

const (
	testUserId   = "user1"
	testUser2Id  = "user2"
	testPassword = "passw0rd"
)

func TestUserMongoRepository_GetUser(t *testing.T) {
	ur := getUserMongoRepo(t, true)
	user, exists := ur.GetUser(testUserId)
	assert.True(t, exists)
	assert.Equal(t, testUserId, user.ID)

	_, exists2 := ur.GetUser("bad")
	assert.False(t, exists2)
}

func TestUserMongoRepository_ValidatePassword(t *testing.T) {
	ur := getUserMongoRepo(t, true)
	tests := []struct {
		name     string
		user     string
		password string
		result   bool
	}{
		{"valid password", testUserId, testPassword, true},
		{"invalid password", testUserId, "bad", false},
		{"invalid user", "bad", testPassword, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ur.ValidatePassword(tt.user, tt.password)
			assert.Equal(t, tt.result, result)
		})
	}
}

func TestUserMongoRepository_CreateUser(t *testing.T) {
	user := models.User{
		ID: testUser2Id,
	}
	ur := getUserMongoRepo(t, true)
	user, err := ur.CreateUser(user)
	assert.NoError(t, err)

	user, exists := ur.GetUser(testUser2Id)
	assert.True(t, exists)
}

func TestUserMongoRepository_SetPassword(t *testing.T) {
	var user = testUserId
	newPassword := "newPassw0rd"
	ur := getUserMongoRepo(t, true)
	err := ur.SetPassword(user, uuid.New().String())
	assert.NoError(t, err)

	result := ur.ValidatePassword(user, newPassword)
	assert.False(t, result)

	err = ur.SetPassword(user, newPassword)
	assert.NoError(t, err)

	result = ur.ValidatePassword(user, newPassword)
	assert.True(t, result)
}

func TestUserMongoRepository_ModifyUser(t *testing.T) {
	repo := getUserMongoRepo(t, true)
	t.Run("test update user", func(t *testing.T) {
		user, ok := repo.GetUser(testUserId)
		assert.True(t, ok)
		assert.Equal(t, testUserId, user.ID)
		(&user).Properties["prop2"] = "value2"
		err := repo.UpdateUser(user)
		assert.NoError(t, err)
		newUser, _ := repo.GetUser(testUserId)
		assert.Equal(t, user.Properties["prop2"], newUser.Properties["prop2"])

	})
	t.Run("test update not existing user", func(t *testing.T) {
		err := repo.UpdateUser(models.User{
			ID:         "bad",
			Properties: nil,
		})
		assert.Error(t, err)
	})
}

func getUserMongoRepo(t *testing.T, drop bool) UserRepository {
	repo, err := NewUserMongoRepository("mongodb://root:changeme@localhost:27017", "users", "users")
	assert.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if drop {
		err = repo.client.Database(repo.db).Drop(ctx)
		assert.NoError(t, err)
	}
	user := models.User{
		ID: testUserId,
		Properties: map[string]string{
			"prop1": "value",
		},
	}
	_, err = repo.CreateUser(user)
	assert.NoError(t, err)
	repo.SetPassword(testUserId, testPassword)

	return repo
}
