package session

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/google/uuid"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoSessionRepository struct {
	client     *mongo.Client
	db         string
	collection string
}

type mongoRepoSession struct {
	Session `bson:",inline"`
}

func NewMongoSessionRepository(uri, db, c string) (*MongoSessionRepository, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	log.Printf("connecting to mongo, uri: %v", uri)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	idxOpt := options.Index()
	idxOpt.SetExpireAfterSeconds(60 * 60 * 24)
	mod := mongo.IndexModel{
		Keys: bson.M{
			"createdAt": 1, // index in ascending order
		}, Options: idxOpt,
	}

	rep := &MongoSessionRepository{
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

func (sr *MongoSessionRepository) CreateSession(session Session) (Session, error) {
	if session.ID == "" {
		session.ID = uuid.New().String()
	}

	session.CreatedAt = time.Now()

	repoSession := mongoRepoSession{
		Session: session,
	}

	collection := sr.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := collection.InsertOne(ctx, &repoSession)
	if err != nil {
		return session, err
	}

	return session, nil
}

func (sr *MongoSessionRepository) DeleteSession(id string) error {
	collection := sr.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	filter := bson.M{"id": id}
	err := collection.FindOneAndDelete(ctx, filter).Err()
	if err != nil {
		return err
	}
	return nil
}

func (sr *MongoSessionRepository) GetSession(id string) (Session, error) {
	var session Session
	collection := sr.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	filter := bson.M{"id": id}

	var repoSession mongoRepoSession
	err := collection.FindOne(ctx, filter).Decode(&repoSession)

	if err != nil {
		return session, err
	}

	return repoSession.Session, nil
}

func (sr *MongoSessionRepository) UpdateSession(session Session) error {
	collection := sr.getCollection()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	filter := bson.M{"id": session.ID}
	var repoSession mongoRepoSession
	err := collection.FindOneAndUpdate(ctx, filter, bson.M{"$set": session}).Decode(&repoSession)

	if err != nil {
		return err
	}
	return nil
}

func (sr *MongoSessionRepository) getCollection() *mongo.Collection {
	return sr.client.Database(sr.db).Collection(sr.collection)
}
