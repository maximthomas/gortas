package repo

import (
	"github.com/google/uuid"
	"os"

	"github.com/maximthomas/gortas/pkg/models"
)

type UserRepository interface {
	GetUser(id string) (models.User, bool)
	ValidatePassword(id, password string) bool
	CreateUser(user models.User) (models.User, error)
	UpdateUser(user models.User) error
	SetPassword(id, password string) error
}

type InMemoryUserRepository struct {
	Users     []models.User
	Realm     string
	passwords map[string]string
}

func (ur *InMemoryUserRepository) GetUser(id string) (user models.User, exists bool) {
	for _, u := range ur.Users {
		if u.ID == id {
			user = u
			exists = true
			break
		}
	}
	return user, exists
}

func (ur *InMemoryUserRepository) ValidatePassword(id, password string) (valid bool) {
	if password == "password" {
		valid = true
	}
	if setPass, ok := ur.passwords[id]; ok {
		if setPass == password {
			valid = true
		}
	}
	return valid
}

func (ur *InMemoryUserRepository) CreateUser(user models.User) (models.User, error) {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	ur.Users = append(ur.Users, user)
	return user, nil
}

func (ur *InMemoryUserRepository) UpdateUser(user models.User) error {
	return nil
}
func (ur *InMemoryUserRepository) SetPassword(id, password string) error {
	ur.passwords[id] = password
	return nil
}

func NewInMemoryUserRepository() UserRepository {

	ds := &InMemoryUserRepository{}
	ds.Users = []models.User{
		{
			ID:    "user1",
			Realm: "users",
			Roles: []string{"admin"},
		},
		{
			ID:    "user2",
			Realm: "users",
			Roles: []string{"manager"},
		},
		{
			ID:    "staff1",
			Realm: "staff",
			Roles: []string{"head_of_it"},
		},
	}
	ds.passwords = make(map[string]string)
	for _, u := range ds.Users {
		ds.passwords[u.ID] = "password"
	}
	return ds
}

func NewUserRepository() UserRepository {
	//ac := config.GetConfig()
	//sr = &RestSessionRepository{Endpoint: ac.Endpoints.SessionService}
	local := os.Getenv("DEV_LOCAL")
	if local == "true" {
		return NewInMemoryUserRepository()
	}
	return nil
}
