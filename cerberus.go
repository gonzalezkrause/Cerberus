// Copyright (C) 2015 José F. González Krause.
// All rights reserved.
// Use of this source code is governed by a GPLv2-style
// license that can be found in the LICENSE file.
// You can contact me under:
// email: rev(ninja [dot] hackercat [at] josef)

package cerberus

import (
	"log"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
)

type Cerberus struct {
	storeName string
}

func NewCerberus(storeName, dbAddr, dbPort, dbName string) *Cerberus {
	sessionDatabase = sessionDataStore{
		dbAddr: dbAddr,
		dbPort: dbPort,
		dbName: dbName,
	}

	session, err := mgo.Dial(sessionDatabase.dbAddr + ":" + sessionDatabase.dbPort)
	if err != nil {
		log.Fatalf("Cerberus: %s", err.Error())
	}

	session.SetMode(mgo.Monotonic, true)

	db := session.DB(dbName)
	sessionDatabase.db = db

	log.Println("Cerberus: Session database conected")

	return &Cerberus{
		storeName: storeName,
	}
}

// ====================
// = Session handlers =
// ====================

// Generate a new tampersafe cookie store
var store = sessions.NewCookieStore(securecookie.GenerateRandomKey(64))

// FIXME: Dev bypass
// var store = sessions.NewCookieStore([]byte{
// 	42, 42, 42, 42, 42, 42, 42, 42,
// 	42, 42, 42, 42, 42, 42, 42, 42,
// 	42, 42, 42, 42, 42, 42, 42, 42,
// 	42, 42, 42, 42, 42, 42, 42, 42,
// 	42, 42, 42, 42, 42, 42, 42, 42,
// 	42, 42, 42, 42, 42, 42, 42, 42,
// 	42, 42, 42, 42, 42, 42, 42, 42,
// 	42, 42, 42, 42, 42, 42, 42, 42,
// })

// SetSession cookie and stores the session entry into the "sessions" collection
func (c *Cerberus) SetSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, c.storeName)
	if err != nil {
		c.UnsetSession(w, r)
		return
	}

	// TODO: make it configurable
	session.Options = &sessions.Options{
		// Domain "localhost"
		// MaxAge=0 means no 'Max-Age' attribute specified.
		// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'.
		// MaxAge>0 means Max-Age attribute present and given in seconds.
		// Path:     "/",
		MaxAge:   86400 * 30,
		Secure:   false, // Change for https
		HttpOnly: false,
	}

	var token []byte
	username := r.FormValue("username")

	// if no valid token in DB
	if data, err := sessionDatabase.getToken(username); err != nil {
		log.Println("Created new session")
		token = securecookie.GenerateRandomKey(64)
		if err := sessionDatabase.insertToken(token, username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		log.Println("Recovered old session")
		username = data.Username
		token = data.Token
	}

	isAdmin := false
	isAdmin, _ = sessionDatabase.checkAdmin(username)

	// Set some session values.
	session.Values["username"] = username
	session.Values["token"] = token
	session.Values["isAdmin"] = isAdmin

	session.Save(r, w)
	return
}

// UnsetSession cookie and deletes the session entry from the "sessions" collection
func (c *Cerberus) UnsetSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, c.storeName)
	if err != nil {
		http.Error(w, MessingArroundError.Error(), http.StatusInternalServerError)
		return
	}

	// Type assert the recoveres cookie values
	var username string
	var token []byte
	username, _ = session.Values["username"].(string)
	token, _ = session.Values["token"].([]byte)

	if err := sessionDatabase.deleteToken(token, username); err != nil {
		http.Error(w, MessingArroundError.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["username"] = ""
	session.Values["token"] = ""

	session.Save(r, w)
	return
}

// GetUsername from the cookie and returns it
func (c *Cerberus) GetUsername(r *http.Request) (string, error) {
	session, err := store.Get(r, c.storeName)
	if err != nil {
		return "", MessingArroundError
	}

	username := session.Values["username"]

	// Type assertion
	if str, ok := username.(string); ok {
		return str, nil
	} else {
		return "", SessionError
	}
}

// Extracts isAdmin flag from the cookie and returns it
func (c *Cerberus) UserIsAdmin(r *http.Request) (bool, error) {
	session, err := store.Get(r, c.storeName)
	if err != nil {
		return false, MessingArroundError
	}

	isAdmin := session.Values["isAdmin"]

	// Type assertion
	if str, ok := isAdmin.(bool); ok {
		return str, nil
	} else {
		return false, SessionError
	}
}

// Check if user exists on the DB
func (c *Cerberus) CheckUser(username, userpass string) error {
	result, err := sessionDatabase.getUser(username)
	if err != nil {
		if err == mgo.ErrNotFound {
			return UserNotExistsError

		} else {
			return err
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(result.Userpass), []byte(userpass)); err != nil {
		return LoginError
	}

	return nil
}

// Check if the token is in the DB stored as valid token
func (c *Cerberus) CheckAuthToken(r *http.Request) error {
	session, err := store.Get(r, c.storeName)
	if err != nil {
		return SessionError
	}

	var username string
	var token []byte
	if data, ok := session.Values["username"].(string); ok {
		username = data
	}
	if data, ok := session.Values["token"].([]byte); ok {
		token = data
	}

	if result, err := sessionDatabase.getToken(username); err != nil {
		log.Println(err)
		return SessionError
	} else {
		if string(result.Token) == string(token) {
			return nil
		}
	}
	return LoginError
}

// =================
// = User handlers =
// =================

// AddNewUser with hashed password
func (c *Cerberus) AddNewUser(username, userpass, email string, isAdmin bool) error {
	// TODO: check for existing username

	// Generate the new password hash
	hash, err := bcrypt.GenerateFromPassword([]byte(userpass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if _, err := sessionDatabase.getUser(username); err == nil {
		return UserAlreadyExistsError
	}

	// log.Printf("&SessionDataStore: %p", &Database)
	if err := sessionDatabase.insertUser(username, string(hash), email, isAdmin); err != nil {
		return err
	}

	return nil
}

// // GetUsername returns user id from the user DB
// func (c *Cerberus) GetUsername(r *http.Request) (string, error) {
// 	session, err := store.Get(r, c.storeName)
// 	if err != nil {
// 		return "", MessingArroundError
// 	}

// 	username := session.Values["username"]

// 	// Type assertion
// 	if str, ok := username.(string); ok {
// 		id, err := sessionDatabase.getUserId(username) {

// 		}
// 	}
// }
