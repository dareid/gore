package roger

import (
	"fmt"
	"testing"
)

func TestClient(t *testing.T) {
	rc, _ := NewRClient("127.0.0.1", 6311)
	fmt.Println(rc)
}

func TestSession(t *testing.T) {
	rc, _ := NewRClient("127.0.0.1", 6311)

	s, err := newSession(rc, "", "")
	fmt.Println("session err: %v", err)
	fmt.Println(s)
	s.close()
}

func TestVoidEval(t *testing.T) {
	rc, _ := NewRClient("127.0.0.1", 6311)
	r_script := `a <- c(1,2,3)
	b <- a
	`
	err := rc.VoidEval(r_script)
	fmt.Println("voidEval err: %v", err)
}
