package roger

import (
	"bytes"
	"image/png"
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

func TestListParsing(t *testing.T) {
	obj, _ := getResultObject("l <- list(); l$int <- as.integer(2); l$float <- 3.2342e04; l$char <- 'test'; l")
	list, ok := obj.(map[string]interface{})
	assert.Equal(t, ok, true, "Return obj should be a map")
	assert.Equal(t, list["int"], int32(2))
	assert.Equal(t, list["float"], float64(32342))
	assert.Equal(t, list["char"], "test")
}

func TestSingleItemListParsing(t *testing.T) {
	obj, err := getResultObject("list(echo=TRUE)")
	assert.Nil(t, err)
	list, ok := obj.(map[string]interface{})
	assert.Equal(t, ok, true, "Return obj should be a map")
	assert.Equal(t, list["echo"], true, "Expecting a 'echo' to equal TRUE")
}

func TestNestedListParsing(t *testing.T) {
	obj, _ := getResultObject("l <- list(); l$top <- 2; l$nested <- list(); l$nested$inner <- 3; l$nested$internal <- c(4,2,1); l")
	list, ok := obj.(map[string]interface{})
	assert.Equal(t, ok, true, "Return obj should be a map")
	assert.Equal(t, list["top"], float64(2))
	nestedList, ok := list["nested"].(map[string]interface{})
	assert.Equal(t, ok, true, "Nested list should be available")
	assert.Equal(t, nestedList["inner"], float64(3))
	assert.Equal(t, nestedList["internal"], []float64{4, 2, 1})
}

func TestRawParsing(t *testing.T) {
	obj, _ := getResultObject("xx <- raw(2); xx[1] <- as.raw(40); xx[2] <- charToRaw(\"A\"); xx")
	assert.Equal(t, obj, []byte{0x28, 0x41})
}

func TestImageParsing(t *testing.T) {
	obj, _ := getResultObject("filename <- tempfile(\"plot\", fileext = \".png\"); png(filename, width = 480, height = 480); plot(1:10); dev.off(); image <- readBin(filename, \"raw\", 29999); image")
	imageBytes, ok := obj.([]byte)
	assert.Equal(t, ok, true, "Image should be returned as a raw byte array")
	reader := bytes.NewReader(imageBytes)
	image, err := png.Decode(reader)
	assert.Equal(t, err, nil, "Returned byte array should be a png")
	assert.Equal(t, image.Bounds().Max.X, 480, "Image should be 480x480")
	assert.Equal(t, image.Bounds().Max.Y, 480, "Image should be 480x480")
}

func TestComplexParsing(t *testing.T) {
	obj, _ := getResultObject("complex(real = 1, imaginary = 2.22)")
	c, ok := obj.(complex128)
	assert.Equal(t, ok, true, "Return obj should be a complex128")
	assert.Equal(t, real(c), float64(1))
	assert.Equal(t, imag(c), float64(2.22))
}

func TestComplexArrayParsing(t *testing.T) {
	obj, _ := getResultObject("c(complex(real = 1, imaginary = 2.22), complex(real = 100, imaginary = -222))")
	cArr, ok := obj.([]complex128)
	assert.Equal(t, ok, true, "Return obj should be an complex128 array")
	assert.Equal(t, cArr, []complex128{complex(1, 2.22), complex(100, -222)})
}

func TestLongResponse(t *testing.T) {
	obj, err := getResultObject("paste(rep(\"a\", 15000000), sep=\"\", collapse = \"\")")
	assert.Nil(t, err)
	str, ok := obj.(string)
	assert.Equal(t, ok, true, "Return obj should be a string")
	assert.Equal(t, len(str), 15000000, "String length expected to be 15000000 characters")
}
