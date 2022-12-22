package user

import (
	"github.com/mitchellh/mapstructure"
)

type UserService struct {
	Repo UserRepository
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
		ur := &UserLdapRepository{}
		err := mapstructure.Decode(prop, ur)
		if err != nil {
			return us, err
		}
		us.Repo = ur
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
		us.Repo = ur
	} else {
		us.Repo = NewInMemoryUserRepository()
	}

	return us, err
}
