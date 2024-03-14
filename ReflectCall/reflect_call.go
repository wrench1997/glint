package reflectcall

import (
	"errors"
	"reflect"
)

func Call(m map[string]interface{}, name string, params ...interface{}) ([]reflect.Value, error) {
	f := reflect.ValueOf(m[name])
	if len(params) != f.Type().NumIn() {
		return nil, errors.New("the number of input params not match!")
	}
	in := make([]reflect.Value, len(params))
	for k, v := range params {
		in[k] = reflect.ValueOf(v)
	}
	return f.Call(in), nil
}
