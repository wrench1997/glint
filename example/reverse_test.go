package mydemo

import (
	"fmt"
	"glint/config"
	"glint/reverse"
	"glint/util"
	"testing"
)

func Test_rverse(t *testing.T) {
	util.Setup()
	flag := "r123451212"
	reverse1 := reverse.NewReverse1(config.CeyeDomain, flag)
	_reverse := reverse1.(*reverse.Reverse1)
	if reverse.ReverseCheck(_reverse, 2) {
		fmt.Printf("ok")
	}
}
