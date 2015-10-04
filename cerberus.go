package cerberus

import (
	"log"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// Fucking global…
var SessionDatabase SessionDataStore

type Cerberus struct {
	StoreName string
}

func NewCerberus(storeName string) *Cerberus {
	return &Cerberus{
		StoreName: storeName,
	}
}

// ====================
// = Session handlers =
// ====================

// Generate a new tampersafe cookie store
// var store = sessions.NewCookieStore(securecookie.GenerateRandomKey(64))

// FIXME: Dev bypass
var store = sessions.NewCookieStore([]byte{
	107, 136, 183, 114, 81, 237, 136, 14,
	208, 189, 211, 56, 11, 164, 77, 121,
	192, 188, 252, 57, 88, 89, 57, 111,
	227, 239, 35, 228, 142, 247, 155, 181,
	154, 175, 8, 133, 178, 88, 86, 12,
	189, 153, 53, 101, 110, 248, 196, 250,
	6, 243, 60, 237, 73, 112, 214, 113,
	139, 186, 107, 121, 35, 248, 19, 64,
})

// Sets the session cookie and stores the session entry to the "sessions" collection
func (c *Cerberus) SetSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, c.StoreName)
	if err != nil {
		// http.Error(w, MessingArroundError.Error(), http.StatusInternalServerError)
		c.UnsetSession(w, r)
		return
	}

	// TODO: Configurable
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
	if data, err := SessionDatabase.getToken(username); err != nil {
		log.Println("Created new session")
		token = securecookie.GenerateRandomKey(64)
		if err := SessionDatabase.insertToken(token, username); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		log.Println("Recovered old session")
		username = data.Username
		token = data.Token
	}

	isAdmin := false
	isAdmin, _ = SessionDatabase.checkAdmin(username)

	// Set some session values.
	session.Values["username"] = username
	session.Values["token"] = token
	session.Values["isAdmin"] = isAdmin

	session.Save(r, w)
	return
}

// Unsets the session cookie and deletes the session entry from the "sessions" collection
func (c *Cerberus) UnsetSession(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, c.StoreName)
	if err != nil {
		http.Error(w, MessingArroundError.Error(), http.StatusInternalServerError)
		return
	}

	// Type assert the recoveres cookie values
	var username string
	var token []byte
	username, _ = session.Values["username"].(string)
	token, _ = session.Values["token"].([]byte)

	if err := SessionDatabase.deleteToken(token, username); err != nil {
		http.Error(w, MessingArroundError.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["username"] = ""
	session.Values["token"] = ""

	session.Save(r, w)
	return
}

// Extracts username from the cookie and returns it
func (c *Cerberus) GetUsername(r *http.Request) (string, error) {
	session, err := store.Get(r, c.StoreName)
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
	session, err := store.Get(r, c.StoreName)
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
	result, err := SessionDatabase.getUser(username)
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
	session, err := store.Get(r, c.StoreName)
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

	if result, err := SessionDatabase.getToken(username); err != nil {
		log.Println(err)
		return SessionError
	} else {
		if string(result.Token) == string(token) {
			return nil
		}
	}
	return LoginError
}

// Add new user with hashed password
func (c *Cerberus) AddNewUser(username, userpass, email string, isAdmin bool) error {
	// TODO: check for existing username

	// Generate the new password hash
	hash, err := bcrypt.GenerateFromPassword([]byte(userpass), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if _, err := SessionDatabase.getUser(username); err == nil {
		return UserAlreadyExistsError
	}

	// log.Printf("&SessionDataStore: %p", &Database)
	if err := SessionDatabase.insertUser(username, string(hash), email, isAdmin); err != nil {
		return err
	}

	return nil
}

// ====================
// = Database methods =
// ====================

// User collection entry struct.
type userDB struct {
	Username string `bson:"username"`
	Userpass string `bson:"userpass"`
	Email    string `bson:"email"`
	IsActive bool   `bson:"isActive"`
	IsAdmin  bool   `bson:"isAdmin"`
}

// Session collection entry struct.
type sessionsDB struct {
	Username string
	Token    []byte
}

// Database connector struct.
type SessionDataStore struct {
	DBAddr string
	DBPort string
	DBName string
	db     *mgo.Database
}

// Connect to de DB and stores the db instance in –SessionDataStore–
func (d *SessionDataStore) Connect() {
	session, err := mgo.Dial(d.DBAddr + ":" + d.DBPort)
	if err != nil {
		log.Fatalf("Cerberus: %s", err.Error())
	}

	session.SetMode(mgo.Monotonic, true)

	db := session.DB(d.DBName)
	d.db = db
	log.Println("Cerberus: Session database conected")
}

// Insert userdata into "users" collection.
func (d *SessionDataStore) insertUser(username, userpass, email string, isAdmin bool) error {
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
func (d *SessionDataStore) insertToken(token []byte, username string) error {
	col := d.db.C("sessions")
	if _, err := col.Upsert(bson.M{"username": username}, &sessionsDB{username, token}); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

// Deletes token from "sessions" collection.
func (d *SessionDataStore) deleteToken(token []byte, username string) error {
	col := d.db.C("sessions")
	query := bson.M{"username": username, "token": token}
	if _, err := col.RemoveAll(query); err != nil {
		log.Println(err)
		return err
	}
	return nil
}

// Search an entry in "users" where "username" is passed username to users
// and returns collection and return a sessionDB struct or error.
func (d *SessionDataStore) getUser(username string) (userDB, error) {
	result := userDB{}
	col := d.db.C("users")
	query := bson.M{"username": username}

	if err := col.Find(query).One(&result); err != nil {
		log.Printf("DB user: %s", err)
		return userDB{}, err
	}

	return result, nil
}

// Search an entry in "sessions" where "username" is passed username to sessions
// and returns collection and returns a sessionDB struct or error.
func (d *SessionDataStore) getToken(username string) (sessionsDB, error) {
	result := sessionsDB{}
	col := d.db.C("sessions")
	query := bson.M{"username": username}

	if err := col.Find(query).One(&result); err != nil {
		log.Printf("Cerberus: %s", err)
		return sessionsDB{}, err
	}

	return result, nil
}

// Check if user has admin flag to true
func (d *SessionDataStore) checkAdmin(username string) (bool, error) {
	result := userDB{}
	col := d.db.C("users")
	query := bson.M{"username": username}

	if err := col.Find(query).One(&result); err != nil {
		log.Printf("Cerberus: %s", err)
		return false, err
	}

	isAdmin := result.IsAdmin

	return isAdmin, nil
}

// Returns all the users
func (d *SessionDataStore) getAllUsers() ([]string, error) {
	var result []string
	query := bson.M{}
	col := d.db.C("users")

	if err := col.Find(query).Distinct("username", &result); err != nil {
		log.Printf("DB - error: %s", err)
		return result, err
	}

	return result, nil
}
