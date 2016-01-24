package roger

import (
	"reflect"
	"runtime/debug"
	"testing"
)

func checkList(t *testing.T, rstring string, result interface{}) {
	defer func() {
		if r := recover(); r != nil {
			t.Error("Panic during test.  ", r, string(debug.Stack()))
		}
	}()

	con, err := NewRClient("localhost", 6311)
	if err != nil {
		t.Error("Could not connect to RServe: " + err.Error())
		return
	}

	v, err := con.Eval(rstring)

	if err != nil {
		t.Error("Error returned by R: " + err.Error())
	}

	if !reflect.DeepEqual(v, result) {
		t.Error("Actual result did not match expected result.")
	}
}

func TestListFloatInts(t *testing.T) {
	checkList(t, "list(int=1,string='s',float=0.5)", map[string]interface{}{"int": 1.0, "string": "s", "float": 0.5})
}

func TestListBoolInMiddle(t *testing.T) {
	checkList(t, "list(int=1,string='s',float=0.5,bool=TRUE,anything='this should not cause a panic')", map[string]interface{}{"int": 1.0, "string": "s", "bool": true, "float": 0.5, "anything": "this should not cause a panic"})
}

func TestOnlyBool(t *testing.T) {
	checkList(t, "list(bool=TRUE,b2=FALSE)", map[string]interface{}{"bool": true, "b2": false})
}
