package sexp

import (
	"errors"
	"log"
)

func parseListNoTagAttr(attr interface{}, listNoTagArr []interface{}, offset int) (interface{}, int, error) {
	attrMap, ok := attr.(map[string]interface{})
	if !ok {
		return listNoTagArr, offset, nil
	}
	names, ok := attrMap["n"].([]string)
	if !ok {
		name, ok := attrMap["n"].(string)
		if !ok {
			return nil, offset, errors.New("List-no-tag names not parsed correctly")
		}
		names = []string{name}
	}
	if len(names) != len(listNoTagArr) {
		return nil, offset, errors.New("List-no-tag name and value quantity mismatch")
	}

	ret := map[string]interface{}{}
	for i := range names {
		ret[names[i]] = listNoTagArr[i]
	}

	return ret, offset, nil
}

func parseListNoTag(attr interface{}, buf []byte, offset, end int) (interface{}, int, error) {
	var listNoTagArr []interface{}

	for offset < end {
		listNoTagEntry, newOffset, err := parseReturningOffset(buf, offset)
		offset = newOffset
		if err != nil {
			log.Println("Warning: Error whilst constructing list-no-tag: " + err.Error())
		} else {
			listNoTagArr = append(listNoTagArr, listNoTagEntry)
		}
	}
	if offset != end {
		log.Println("Warning: vector size mismatch")
		offset = end
	}
	//	return parseListNoTagAttr(attr, listNoTagArr, offset)
	return listNoTagArr, offset, nil
}
