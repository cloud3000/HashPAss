# Hashing Passwords with bcrypt.
 hashpass is a set of functions utilizing bcrypt to assist in storing hashed passwords for new user registration, and password/hash comparison for user authentication.

Here is an example of how it might be used.

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

    "golang.org/x/crypto/bcrypt"
    "github.com/cloud3000/hashpass"
)

type credential struct {
	Username     string `json:"Username"`
	Hashpassword string `json:"Hashpassword"`
}

func main() {
	passdb := "pass.json" // JSON file where passwords are stored.
	cmd, usr, pas, err := getInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	badpass, err := chkBadpass(pas)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}

	if badpass {
		fmt.Fprintf(os.Stderr, "Overused Password NOT ALLOWED! [%s]\n", pas)
		os.Exit(2)
	}

	switch strings.ToLower(cmd) {
	case "store":
		err = storePass(usr, pas, passdb)
	case "check":
		err = checkPass(usr, pas, passdb)
	default:
		err = fmt.Errorf("%s is not a valid command", cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}
```
ToDo's: 
Add config.json, and code to support it.
Add code to check for pre-existing user before appending a new record to ./data/pass.db
