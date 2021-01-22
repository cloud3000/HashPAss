# Hashing Passwords with bcrypt.
 hashpass is a set of functions utilizing bcrypt to assist in storing hashed passwords for new user registration, and password/hash comparison for user authentication.

Here is an example of how it might be used.

```go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/cloud3000/hashpass"
)

func main() {
	passdb := "pass.json" // JSON file where passwords are stored.
	cmd, usr, pas, err := hashpass.GetInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if hashpass.ChkBadpass(pas) {
		fmt.Fprintf(os.Stderr, "Overused Password NOT ALLOWED! [%s]\n", pas)
		os.Exit(2)
	}
	var cc uint8 = 0
	switch strings.ToLower(cmd) {
	case "store":
		n, err := hashpass.StorePass(usr, pas, passdb)
		if n == 0 {
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "StorePass failed to write any data")
			}
		}
	case "check":
		cc, err = hashpass.CheckPass(usr, pas, passdb)
		if cc != 1 {
			if err != nil {
				fmt.Fprintf(os.Stderr, "CheckPass Error: %v", err)
			} else {
				fmt.Fprintf(os.Stderr, "Invalid Credentials")
			}
		}
	default:
		err = fmt.Errorf("%s is not a valid command", cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
	}
}


```
ToDo's: 
1. Add config.json, and code to support it.
