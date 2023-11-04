package src

import (
	"backend/models"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
)

func ValidateNewUserInput(userdata *models.NewUser) error {
	//check for missing fields
	if userdata.Private == nil {
		return errors.New("Invalid or missing privateAccount field")
	}
	if userdata.UserName == "" {
		return errors.New("Missing username")
	}
	if userdata.Password == "" {
		return errors.New("Missing password field")
	}
	if userdata.Email == "" {
		return errors.New("Missing email field")
	}
	if userdata.PhoneNumber == "" {
		return errors.New("Missing phone number field")
	}
	if userdata.UserName == "" {
		return errors.New("Missing userName field")
	}
	if userdata.DOB == "" {
		return errors.New("Missing DOB field")
	}
	if userdata.Bio == nil {
		return errors.New("Missing bio field")
	}
	if userdata.Name == "" {
		return errors.New("Missing name field")
	}

	// user name validation

	match, _ := regexp.MatchString("^[a-zA-Z0-9][a-zA-Z0-9_]*$", userdata.UserName)
	if !match {
		return errors.New("User name should start with alphabet and can have combination minimum 8 characters of numbers and only underscore(_)")
	}

	if len(userdata.UserName) < 7 || len(userdata.UserName) > 20 {
		return errors.New("Username should be of length(7,20)")
	}

	if len(userdata.Name) > 20 {
		return errors.New("Name should be less than 20 character")
	}

	// user password validation
	if len(userdata.Password) == 0 {
		return errors.New("Missing password field")
	}

	match, _ = regexp.MatchString("[0-9]+?", userdata.Password)
	if !match {
		return errors.New("Password must contain atleast one number")
	}
	match, _ = regexp.MatchString("[A-Z]+?", userdata.Password)
	if !match {
		return errors.New("Password must contain atleast upper case letter")
	}
	match, _ = regexp.MatchString("[a-z]+?", userdata.Password)
	if !match {
		return errors.New("Password must contain atleast lower case letter")
	}
	match, _ = regexp.MatchString("[!@#$%^&*_]+?", userdata.Password)
	if !match {
		return errors.New("Password must contain atleast special character")
	}
	match, _ = regexp.MatchString(".{8,30}", userdata.Password)
	if !match {
		return errors.New("Password length must be atleast 8 character long")
	}

	//phone number validation
	match, _ = regexp.MatchString("^[+]{1}[0-9]{0,3}\\s?[0-9]{10}$", userdata.PhoneNumber)
	if !match {
		return errors.New("Please enter valid phone number")
	}

	//validate email using net/mail
	emailregex := regexp.MustCompile("^[A-Za-za0-9.!#$%&'*+\\/=?^_`{|}~-]+@[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
	match = emailregex.MatchString(userdata.Email)
	if !match {
		return errors.New("Enter valid email")
	}
	if len(userdata.Email) < 3 && len(userdata.Email) > 254 {
		return errors.New("Invalid email")
	}

	i := strings.Index(userdata.Email, "@")
	host := userdata.Email[i+1:]

	_, err := net.LookupMX(host)
	if err != nil {
		return errors.New("Invalid email(host not found)")
	}
	//validate date
	layout := "2006-01-02"
	bdate, err := time.Parse(layout, userdata.DOB)
	if err != nil {
		return errors.New("Enter a valid date format")
	}
	cdate := time.Now()

	age := cdate.Sub(bdate)
	if age.Hours() < 113958 {
		return errors.New("Enter proper date of birth,You ahould be minimum of 13 years old to create an account")
	}
	return nil
}
