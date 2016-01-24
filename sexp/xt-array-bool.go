package sexp

import "encoding/binary"

func parseBoolArray(buf []byte, offset int, end int) (interface{}, int, error) {
	boolArrayLen := binary.LittleEndian.Uint32(buf[offset : offset+4])
	offset = offset + 4

	boolArr := make([]bool, 0, boolArrayLen)
	for ct := uint32(0); ct < boolArrayLen; ct++ {
		b := buf[offset]
		if b == 1 {
			boolArr = append(boolArr, true)
		} else if b == 0 {
			boolArr = append(boolArr, false)
		}
		offset = offset + 1
	}

	if len(boolArr) == 1 {
		return boolArr[0], end, nil
	}

	return boolArr, end, nil
}
