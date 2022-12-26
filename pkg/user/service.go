package user

import (
	"github.com/mitchellh/mapstructure"
)

type UserService struct {
	repo userRepository
}

func (us UserService) GetUser(id string) (user User, exists bool) {
	return us.repo.GetUser(id)
}

func (us UserService) ValidatePassword(id, password string) (valid bool) {
	return us.repo.ValidatePassword(id, password)
}

func (us UserService) CreateUser(user User) (User, error) {
	return us.repo.CreateUser(user)
}

func (us UserService) UpdateUser(usr User) error {
	return us.repo.UpdateUser(usr)
}

func (us UserService) SetPassword(id, password string) error {
	return us.repo.SetPassword(id, password)
}

var us UserService

func InitUserService(uc UserConfig) error {
	newUs, err := newUserService(uc)
	if err != nil {
		return err
	}
	us = newUs
	return nil
}

func GetUserService() UserService {
	return us
}

func SetUserService(newUs UserService) {
	us = newUs
}

func newUserService(uc UserConfig) (us UserService, err error) {

	if uc.Type == "ldap" {
		prop := uc.Properties
		ur := &userLdapRepository{}
		err := mapstructure.Decode(prop, ur)
		if err != nil {
			return us, err
		}
		us.repo = ur
	} else if uc.Type == "mongodb" {
		prop := uc.Properties
		params := make(map[string]interface{})
		err := mapstructure.Decode(&prop, &params)
		if err != nil {
			return us, err
		}
		url, _ := params["url"].(string)
		db, _ := params["database"].(string)
		col, _ := params["collection"].(string)
		ur, err := NewUserMongoRepository(url, db, col)
		if err != nil {
			return us, err
		}
		us.repo = ur
	} else {
		us.repo = NewInMemoryUserRepository()
	}

	return us, err
}
