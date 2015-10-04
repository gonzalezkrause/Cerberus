// Copyright (C) 2015 José F. González Krause.
// All rights reserved.
// Use of this source code is governed by a GPLv2-style
// license that can be found in the LICENSE file.
// You can contact me under:
// email: rev(ninja [dot] hackercat [at] josef)

package cerberus

// ====================
// = Database methods =
// ====================

import (
	"log"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var sessionDatabase sessionDataStore

// User collection entry struct.
type userDB struct {
	Username string `bson:"_id"`
	Userpass string `bson:"userpass"`
	Email    string `bson:"email"`
	IsActive bool   `bson:"isActive"`
	IsAdmin  bool   `bson:"isAdmin"`
}

// Session collection entry struct.
type sessionsDB struct {
	Username string `bson:"_id"`
	Token    []byte `bson:"token"`
}

// Database connector struct.
type sessionDataStore struct {
	dbAddr string
	dbPort string
	dbName string
	db     *mgo.Database
}

// Insert userdata into "users" collection.
func (d *sessionDataStore) insertUser(username, userpass, email string, isAdmin bool) error {
	col := d.db.C("users")
	data := &userDB{
		Username: username,
		Userpass: userpass,
		Email:    email,
		IsActive: true,
		IsAdmin:  isAdmin,
	}

	if err := col.Insert(data); err != nil {
		log.Println(err)
		return err
	}

	return nil
}

// Insert token into "sessions" collection.
func (d *sessionDataStore) insertToken(token []byte, username string) error {
	col := d.db.C("sessions")
	query := bson.M{"_id": username}
	data := &sessionsDB{username, token}

	if _, err := col.Upsert(query, data); err != nil {
		log.Println(err)
		return err
	}

	return nil
}

// Deletes token from "sessions" collection.
func (d *sessionDataStore) deleteToken(token []byte, username string) error {
	col := d.db.C("sessions")
	query := bson.M{"_id": username, "token": token}

	if _, err := col.RemoveAll(query); err != nil {
		log.Println(err)
		return err
	}

	return nil
}

// Search an entry in "users" where "username" is passed username to users
// and returns collection and return a sessionDB struct or error.
func (d *sessionDataStore) getUser(username string) (userDB, error) {
	result := userDB{}
	col := d.db.C("users")
	query := bson.M{"_id": username}

	if err := col.Find(query).One(&result); err != nil {
		log.Printf("DB user: %s", err)
		return userDB{}, err
	}

	return result, nil
}

// Search an entry in "sessions" where "username" is passed username to sessions
// and returns collection and returns a sessionDB struct or error.
func (d *sessionDataStore) getToken(username string) (sessionsDB, error) {
	result := sessionsDB{}
	col := d.db.C("sessions")
	query := bson.M{"_id": username}

	if err := col.Find(query).One(&result); err != nil {
		log.Printf("Cerberus: %s", err)
		return sessionsDB{}, err
	}

	return result, nil
}

// Check if user has admin flag to true
func (d *sessionDataStore) checkAdmin(username string) (bool, error) {
	result := userDB{}
	col := d.db.C("users")
	query := bson.M{"_id": username}

	if err := col.Find(query).One(&result); err != nil {
		log.Printf("Cerberus: %s", err)
		return false, err
	}

	isAdmin := result.IsAdmin

	return isAdmin, nil
}

// getAllUsers returns a string array populated with all the users in the db
func (d *sessionDataStore) getAllUsers() ([]string, error) {
	var result []string
	query := bson.M{}
	col := d.db.C("users")

	if err := col.Find(query).Distinct("_id", &result); err != nil {
		log.Printf("DB - error: %s", err)
		return result, err
	}

	return result, nil
}
