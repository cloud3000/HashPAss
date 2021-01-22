package hashpass

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"golang.org/x/crypto/bcrypt"
)

type credential struct {
	Username     string `json:"Username"`
	Hashpassword string `json:"Hashpassword"`
}

// GetInfo will get command-line parms; cmd, usr, and pas
func GetInfo() (string, string, string, error) {
	var cmd, usr, pas string
	if len(os.Args) > 3 {
		cmd = os.Args[1]
		usr = os.Args[2]
		pas = os.Args[3]
	} else {
		return "", "", "", fmt.Errorf("command, user and password are required on the command-line")
	}
	return cmd, usr, pas, nil
}

// StorePass Stores Username(u) and Password(p) in the Flatfile database(db)
//	1. Generates the hash value from the password(p)
//  2. Populates credential with Username & Password
//  3. Marshal credential into json
//  4. Appends single record json string to Flatfile(db)
//  5. TODO: Before appending, check if username already exists in db.
func StorePass(u, p, db string) error {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("Error in hashPassword %w", err)
	}
	fd, err := os.OpenFile(db, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		err = fmt.Errorf("Unable to open: %s: %w", db, err)
	}
	defer fd.Close()
	var userPass credential
	userPass.Username = u
	userPass.Hashpassword = string(hashedPass)
	rec, _ := json.Marshal(&userPass)
	fmt.Fprintf(fd, "%s\n", rec)
	return nil
}

func readln(r *bufio.Reader) (string, error) {
	var (
		isPrefix bool  = true
		err      error = nil
		line, ln []byte
	)
	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}
	return string(ln), err
}

// CheckPass Finds the (db) record that matches username(u)
// Compares clear-text password to hashed value found in db
func CheckPass(u, p, db string) error {
	f, err := os.Open(db)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	r := bufio.NewReader(f)
	var chk, passed credential
	s, e := readln(r)
	for e == nil {
		err = json.Unmarshal([]byte(s), &chk)
		if chk.Username == u {
			err = bcrypt.CompareHashAndPassword([]byte(chk.Hashpassword), []byte(p))
			if err != nil {
				e = fmt.Errorf("Invalid credentials")
			} else {
				passed = chk
				e = fmt.Errorf("Logged in as %s", passed.Username)
			}
		} else {
			s, e = readln(r)
		}
	}
	if e == fmt.Errorf("EOF") { // True when username is not found
		e = fmt.Errorf("Invalid credentials")
	}

	return e
}

// ChkBadpass scans a file (top 1000 most common passwords) looking for a match
// If a match is found return true, and the password should be allowed.
func ChkBadpass(text string) bool {
	ret := false
	data, err := ioutil.ReadFile("badpasswd.txt")
	if err != nil {
		// Error reading badpasswd.txt
		// The error is ignored for now, and false is returned.
		return ret
	}
	str := string(data)
	strlen := len(str)
	txtlen := len(text)

	for i := 0; i < strlen || ret == true; i++ {
		if i+txtlen > strlen { // Id the password length > the remainder of the file.
			break
		} else {
			if str[i:i+txtlen] == text { // Return true when a match is found
				ret = true
			}
		}
	}
	return ret
}
