package user

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type userRestRepository struct {
	realm    string
	endpoint string
	client   http.Client
}

func (ur *userRestRepository) GetUser(id string) (user User, exists bool) {

	resp, err := ur.client.Get(ur.endpoint + "/users/" + id)
	if err != nil {
		log.Printf("error getting user: %v", err)
		return user, exists
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("got bad response from user service: %v", resp)
		return user, exists
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error getting user: %v", err)
		return user, exists
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		log.Printf("error unmarshalling user: %v", err)
		return user, exists
	}
	log.Printf("got user user: %v", user)
	exists = true
	return user, exists
}

func (ur *userRestRepository) ValidatePassword(id, password string) (valid bool) {

	pr := Password{
		Password: password,
	}

	prBytes, err := json.Marshal(pr)
	if err != nil {
		return valid
	}

	buf := bytes.NewBuffer(prBytes)
	resp, err := ur.client.Post(ur.endpoint+"/users/"+id+"/validatepassword", "application/json", buf)
	if err != nil {
		log.Printf("error validating password: %v", err)
		return valid
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		log.Printf("got bad response from user service: %v", resp)
		return valid
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("error validating password: %v", err)
		return valid
	}
	var vpr ValidatePasswordResult

	err = json.Unmarshal(body, &vpr)
	if err != nil {
		log.Printf("error validating password: %v", err)
		return valid
	}
	valid = vpr.Valid

	log.Printf("password validation result for user: %v %v", id, valid)

	return valid
}

func (ur *userRestRepository) CreateUser(user User) (User, error) {
	return user, nil
}

func (ur *userRestRepository) UpdateUser(user User) error {
	return nil
}
func (ur *userRestRepository) SetPassword(id, password string) error {
	return nil
}

func NewUserRestRepository(realm, endpoint string) userRestRepository {
	return userRestRepository{
		realm:    realm,
		endpoint: endpoint,
	}
}
