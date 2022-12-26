package user

import (
	"github.com/google/uuid"
)

type userRepository interface {
	GetUser(id string) (User, bool)
	ValidatePassword(id, password string) bool
	CreateUser(user User) (User, error)
	UpdateUser(user User) error
	SetPassword(id, password string) error
}

type inMemoryUserRepository struct {
	Users     []User
	Realm     string
	passwords map[string]string
}

func (ur *inMemoryUserRepository) GetUser(id string) (user User, exists bool) {
	for _, u := range ur.Users {
		if u.ID == id {
			user = u
			exists = true
			break
		}
	}
	return user, exists
}

func (ur *inMemoryUserRepository) ValidatePassword(id, password string) (valid bool) {
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

func (ur *inMemoryUserRepository) CreateUser(user User) (User, error) {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	ur.Users = append(ur.Users, user)
	return user, nil
}

func (ur *inMemoryUserRepository) UpdateUser(usr User) error {
	for i, u := range ur.Users {
		if u.ID == usr.ID {
			ur.Users[i] = usr
			break
		}
	}
	return nil
}

func (ur *inMemoryUserRepository) SetPassword(id, password string) error {
	ur.passwords[id] = password
	return nil
}

func NewInMemoryUserRepository() userRepository {

	ds := &inMemoryUserRepository{}
	ds.Users = []User{
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
