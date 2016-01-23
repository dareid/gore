package sexp

var rootList []interface{}

func parseLang(buf []byte, offset, end int) (interface{}, int, error) {
	isRoot := false
	if rootList == nil {
		rootList = make([]interface{}, 0)
		isRoot = true
	}

	var headf, tagf interface{}
	var err error
	headf, offset, err = parseReturningOffset(buf, offset)
	if err != nil {
		return nil, offset, err
	}
	rootList = append(rootList, headf)
	_, offset, err = parseReturningOffset(buf, offset)

	if offset < end {
		tagf, offset, err = parseReturningOffset(buf, offset)
		_ = tagf
	}

	var rtn interface{}
	if isRoot {
		rtn = rootList
		rootList = nil
	}
	return rtn, offset, nil
}
