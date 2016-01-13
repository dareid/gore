package sexp

import (
	"errors"
	"log"
)

func parseExpVectorAttr(attr interface{}, expVectorArr []interface{}, offset int) (interface{}, int, error) {
	attrMap, ok := attr.(map[string]interface{})
	if !ok {
		return expVectorArr, offset, nil
	}
	names, ok := attrMap["n"].([]string)
	if !ok {
		name, ok := attrMap["n"].(string)
		if !ok {
			return nil, offset, errors.New("Exp-vector names not parsed correctly")
		}
		names = []string{name}
	}
	if len(names) != len(expVectorArr) {
		return nil, offset, errors.New("Exp-vector names and value quantity mismatch")
	}

	ret := map[string]interface{}{}
	for i := range names {
		ret[names[i]] = expVectorArr[i]
	}

	return ret, offset, nil
}

func parseExpVector(attr interface{}, buf []byte, offset, end int) (interface{}, int, error) {
	var expVectorArr []interface{}

	for offset < end {
		expVectorEntry, newOffset, err := parseReturningOffset(buf, offset)
		offset = newOffset
		if err != nil {
			log.Println("Warning: Error whilst constructing exp-vector: " + err.Error())
		} else {
			expVectorArr = append(expVectorArr, expVectorEntry)
		}
	}
	if offset != end {
		log.Println("Warning: exp-vector size mismatch")
		offset = end
	}
	return parseExpVectorAttr(attr, expVectorArr, offset)
}
