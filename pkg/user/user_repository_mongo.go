package user

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const (
	dbSessionExpireHours         = 24
	mongoDBConnectTimeoutSeconds = 10
)

type userMongoRepository struct {
	client     *mongo.Client
	db         string
	collection string
}

type mongoRepoUser struct {
	User     `bson:",inline"`
	Password string `json:"password,omitempty"`
}

func (ur *userMongoRepository) GetUser(id string) (User, bool) {
	var user User
	collection := ur.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	filter := bson.M{"id": id}

	var repoUser mongoRepoUser
	err := collection.FindOne(ctx, filter).Decode(&repoUser)

	if err != nil {
		return user, false
	}

	return repoUser.User, true
}

func (ur *userMongoRepository) ValidatePassword(id, password string) bool {
	collection := ur.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	filter := bson.M{"id": id}
	var repoUser mongoRepoUser
	err := collection.FindOne(ctx, filter).Decode(&repoUser)
	var valid bool
	if err != nil {
		return valid
	}

	// Comparing the password with the hash
	err = bcrypt.CompareHashAndPassword([]byte(repoUser.Password), []byte(password))
	if err == nil {
		valid = true
	}
	//valid = repoUser.Password == password

	return valid
}

func (ur *userMongoRepository) CreateUser(user User) (User, error) {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	repoUser := mongoRepoUser{
		User:     user,
		Password: "",
	}
	collection := ur.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, &repoUser)
	if err != nil {
		return user, err
	}

	return user, nil
}

func (ur *userMongoRepository) UpdateUser(user User) error {
	collection := ur.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	filter := bson.M{"id": user.ID, "realm": user.Realm}
	var updatedUser mongoRepoUser
	err := collection.FindOneAndUpdate(ctx, filter, bson.M{"$set": user}).Decode(&updatedUser)

	if err != nil {
		return err
	}

	return nil
}

func (ur *userMongoRepository) SetPassword(id, password string) error {
	collection := ur.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		return err
	}

	filter := bson.M{"id": id}
	var updatedUser mongoRepoUser
	err = collection.FindOneAndUpdate(ctx, filter, bson.M{"$set": bson.M{"password": hashedPassword}}).Decode(&updatedUser)

	if err != nil {
		return err
	}

	return nil
}

func newUserMongoRepository(uri, db, c string) (*userMongoRepository, error) {
	ctx, cancel := context.WithTimeout(context.Background(), mongoDBConnectTimeoutSeconds*time.Second)
	defer cancel()
	log.Printf("connecting to mongo, uri: %v", uri)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	idxOpt := options.Index()
	idxOpt.SetExpireAfterSeconds(60 * 60 * dbSessionExpireHours)
	mod := mongo.IndexModel{
		Keys: bson.M{
			"createdAt": 1, // index in ascending order
		}, Options: idxOpt,
	}

	rep := &userMongoRepository{
		client:     client,
		db:         db,
		collection: c,
	}

	_, err = rep.getCollection().Indexes().CreateOne(ctx, mod)
	if err != nil {
		return nil, err
	}
	return rep, nil
}

func (ur *userMongoRepository) getCollection() *mongo.Collection {
	return ur.client.Database(ur.db).Collection(ur.collection)
}
