package roger

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func getResultObject(command string) (interface{}, error) {
	client, _ := NewRClient("localhost", 6311)
	return client.Eval(command)
}

func TestBoolParsing(t *testing.T) {
	obj, _ := getResultObject("TRUE")
	boolean, ok := obj.(bool)
	assert.Equal(t, ok, true, "Return obj should be a boolean")
	assert.Equal(t, boolean, true)
}

func TestBoolArrayParsing(t *testing.T) {
	obj, _ := getResultObject("c(TRUE, FALSE, TRUE)")
	boolArr, ok := obj.([]bool)
	assert.Equal(t, ok, true, "Return obj should be a boolean array")
	assert.Equal(t, boolArr, []bool{true, false, true}, "Return obj should contain the correct booleans")
}

func TestStringParsing(t *testing.T) {
	obj, _ := getResultObject("'testing string'")
	str, ok := obj.(string)
	assert.Equal(t, ok, true, "Return obj should be a string")
	assert.Equal(t, str, "testing string")
}

func TestStringArrayParsing(t *testing.T) {
	obj, _ := getResultObject("c('test', 'string 2', '°')")
	strArr, ok := obj.([]string)
	assert.Equal(t, ok, true, "Return obj should be a string array")
	assert.Equal(t, strArr, []string{"test", "string 2", "°"})
}

func TestIntParsing(t *testing.T) {
	obj, _ := getResultObject("as.integer(2147483647)")
	in, ok := obj.(int32)
	assert.Equal(t, ok, true, "Return obj should be an int32")
	assert.Equal(t, in, int32(2147483647))
}

func TestIntArrayParsing(t *testing.T) {
	obj, _ := getResultObject("c(as.integer(2), as.integer(30000), as.integer(-20000))")
	strArr, ok := obj.([]int32)
	assert.Equal(t, ok, true, "Return obj should be an int32 array")
	assert.Equal(t, strArr, []int32{2, 30000, -20000})
}

func TestDoubleParsing(t *testing.T) {
	obj, _ := getResultObject("2147483647")
	double, ok := obj.(float64)
	assert.Equal(t, ok, true, "Return obj should be a float64")
	assert.Equal(t, double, float64(2147483647))
}

func TestDoubleArrayParsing(t *testing.T) {
	obj, _ := getResultObject("c(2, 2.3213413213213, 3e09, -420318392.2222)")
	doubleArr, ok := obj.([]float64)
	assert.Equal(t, ok, true, "Return obj should be a float64 array")
	assert.Equal(t, doubleArr, []float64{2, 2.3213413213213, 3000000000, -420318392.2222})
}
