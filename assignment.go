package roger

import (
	"fmt"
	"reflect"
	"strings"
)

//struct reflect and variable assignment
func (r *session) prepareAssignment(m interface{}) string {
	//split function strings to []string
	split := func(s string) (out []string) {
		out = strings.FieldsFunc(s, func(r rune) bool {
			switch r {
			case ',', ' ', ';':
				return true
			}
			return false
		})
		return out
	}

	r_assignment_str := ""
	val := reflect.ValueOf(m).Elem()
	for i := 0; i < val.NumField(); i++ {
		r_var := val.Type().Field(i).Tag.Get("r")
		if r_var == "" {
			continue
		}
		r_value := val.Field(i).Interface()
		r_value_str := ""
		switch r_value.(type) {
		default:
			r_value_str = r_value.(string)
		}

		r_value_list := split(r_value_str)
		//loop and construct r assignment string
		t_str := ""
		for i, item := range r_value_list {
			if i == 0 {
				t_str = t_str + fmt.Sprintf("%v", item)
			} else {
				t_str = t_str + fmt.Sprintf(",%v", item)
			}
		}
		t_str = fmt.Sprintf("%v <- c(%v)", r_var, t_str)
		r_assignment_str = r_assignment_str + fmt.Sprintf("%v\n", t_str)
	}
	return r_assignment_str
}

func (s *session) StructToR(m interface{}) error {
	r_assignment_str := s.prepareAssignment(m)
	packet := s.SendCommand(r_assignment_str)
	_, err := packet.GetResultObject()
	return err
}
