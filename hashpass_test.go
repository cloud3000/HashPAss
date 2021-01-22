package hashpass_test

import (
	"testing"

	"hashpass"
)

func TestGetInfo(t *testing.T) {
	//passdb := "pass.json" // JSON file where passwords are stored.
	_, _, _, err := hashpass.GetInfo()
	if err == nil {
		t.Error("Should have returned an error")
	}
}

func TestChkBadpass(t *testing.T) {
	if hashpass.ChkBadpass("asdqwe123") == false {
		t.Fatal("Should be True")
	}
	if hashpass.ChkBadpass("4Windows_Up_His_A55") == true {
		t.Fatal("Should be False")
	}
}
func TestStorePass(t *testing.T) {
	n, err := hashpass.StorePass("janedoe", "10_Snakes_On_A_Plane", "data/pass.json")
	if err != nil {
		t.Fatalf("StorePass return err: %s", err)
	}
	if n < 1 {
		t.Fatal("No data written to db")
	}
}

func TestCheckPass(t *testing.T) {
	stat, err := hashpass.CheckPass("janedoe", "10_Snakes_On_A_Plane", "data/pass.json")
	if err != nil {
		t.Fatalf("CheckPass return err: %s", err)
	}
	if stat == 0 {
		t.Fatal("CheckPass failed to validate, valid credential ")
	}
}
