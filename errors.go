package cerberus

import (
	"errors"
)

var LoginError = errors.New("Login error.")
var SessionError = errors.New("Session error.")
var UserNotExistsError = errors.New("User does not exist error.")
var MessingArroundError = errors.New("Are you mesing arround with my data? Good luck!")
var UserAlreadyExistsError = errors.New("User already exists.")
