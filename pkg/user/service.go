package user

import (
	"github.com/mitchellh/mapstructure"
)

type Service struct {
	repo userRepository
}

func (us Service) GetUser(id string) (user User, exists bool) {
	return us.repo.GetUser(id)
}

func (us Service) ValidatePassword(id, password string) (valid bool) {
	return us.repo.ValidatePassword(id, password)
}

func (us Service) CreateUser(user User) (User, error) {
	return us.repo.CreateUser(user)
}

func (us Service) UpdateUser(usr User) error {
	return us.repo.UpdateUser(usr)
}

func (us Service) SetPassword(id, password string) error {
	return us.repo.SetPassword(id, password)
}

var us Service

func InitUserService(uc Config) error {
	newUs, err := newUserService(uc)
	if err != nil {
		return err
	}
	us = newUs
	return nil
}

func GetUserService() Service {
	return us
}

func SetUserService(newUs Service) {
	us = newUs
}

func newUserService(uc Config) (us Service, err error) {

	if uc.Type == "ldap" {
		prop := uc.Properties
		ur := &userLdapRepository{}
		err = mapstructure.Decode(prop, ur)
		if err != nil {
			return us, err
		}
		us.repo = ur
	} else if uc.Type == "mongodb" {
		prop := uc.Properties
		params := make(map[string]interface{})
		err = mapstructure.Decode(&prop, &params)
		if err != nil {
			return us, err
		}
		url, _ := params["url"].(string)
		db, _ := params["database"].(string)
		col, _ := params["collection"].(string)
		var ur *userMongoRepository
		ur, err = newUserMongoRepository(url, db, col)
		if err != nil {
			return us, err
		}
		us.repo = ur
	} else {
		us.repo = NewInMemoryUserRepository()
	}

	return us, err
}
