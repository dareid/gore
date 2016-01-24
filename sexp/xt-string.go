package sexp

func parseString(buf []byte, offset, end int) (interface{}, int, error) {
	endOfString := offset
	if buf[endOfString] != 0 && endOfString < end {
		endOfString = endOfString + 1
	}
	return []string{string(buf[offset:endOfString])}, end, nil
}
