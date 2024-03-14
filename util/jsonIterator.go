package util

import (
	"encoding/json"
	"reflect"
	"sync"

	"github.com/barkimedes/go-deepcopy"
)

// // JSONKeyValueIterator 是用于迭代JSON键值的函数类型
// type JSONKeyValueIterator func(key string, value interface{})
// // SetAllKeys 将为JSON数据的每个键设置指定值
// func SetAllKeys(data []byte, value interface{}, iter JSONKeyValueIterator) {
// 	var objMap map[string]interface{}
// 	err := json.Unmarshal(data, &objMap	)
// 	if err != nil {
// 		panic(err)
// 	}

// 	// 递归遍历JSON对象，对于每个键调用迭代器函数并设置指定的值
// 	for key, val := range objMap {
// 		iter(key, value)
// 		switch v := val.(type) {
// 		case map[string]interface{}:
// 			SetAllKeys(objToBytes(v), value, iter)
// 		case []interface{}:
// 			for _, u := range v {
// 				switch u.(type) {
// 				case map[string]interface{}:
// 					SetAllKeys(objToBytes(u.(map[string]interface{})), value, iter)
// 				}
// 			}
// 		}
// 	}
// }

// // objToBytes 将JSON对象转换为字节数组
// func objToBytes(objMap map[string]interface{}) []byte {
// 	data, err := json.Marshal(objMap)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return data
// }

// 记录json的key值，并按照维度进行区分，这样的一维排序不会乱
type jsonkeydimension struct {
	key       string
	keyindex  int
	dimension int
}

type JSONKeyValueIterator struct {
	WheretoValue int
	targetlength int
	storetarget  interface{}
	storeSort    map[int]jsonkeydimension
	storecount   int
	lock         sync.Mutex
}

func (jkd *jsonkeydimension) Dimension() int {
	return jkd.dimension
}

func (jkd *jsonkeydimension) Key() string {
	return jkd.key
}

func (jkd *jsonkeydimension) KeyIndex() int {
	return jkd.keyindex
}

// func (ji *JSONKeyValueIterator) String() string {
// 	rawdata, err := json.Marshal(ji.storetarget)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return string(rawdata)
// }

func (ji *JSONKeyValueIterator) Copytarget(dest interface{}) {
	ji.lock.Lock()
	defer ji.lock.Unlock()
	var err error
	ji.storetarget, err = deepcopy.Anything(dest)
	ji.storeSort = make(map[int]jsonkeydimension)
	if err != nil {
		panic(err.Error())
	}
}

func (ji *JSONKeyValueIterator) GetstoreSort() map[int]jsonkeydimension {
	ji.lock.Lock()
	defer ji.lock.Unlock()
	return ji.storeSort
}

func (ji *JSONKeyValueIterator) Reset(dest interface{}) (interface{}, error) {
	ji.lock.Lock()
	defer ji.lock.Unlock()
	ji.targetlength = 0
	ji.storecount = 0
	ji.storeSort = make(map[int]jsonkeydimension)
	return deepcopy.Anything(ji.storetarget)
}

func (ji *JSONKeyValueIterator) parser(data interface{}, dimension int, keyindex int) int {
	switch reflect.TypeOf(data).Kind() {
	case reflect.Map:
		mapValue := reflect.ValueOf(data)
		for _, key := range mapValue.MapKeys() {
			//fmt.Println(mapValue.MapIndex(key).Interface())
			sub := mapValue.MapIndex(key).Interface()
			sub1 := reflect.TypeOf(sub).Kind()
			if sub1 != reflect.Slice {
				ji.parser(mapValue.MapIndex(key).Interface(), dimension, keyindex)
				ji.storeSort[ji.storecount] = jsonkeydimension{dimension: dimension, key: key.String(), keyindex: keyindex}
				ji.storecount++
				ji.targetlength++
				//fmt.Printf("reflect.Map count:%d\n", ji.targetlength)
			} else {
				ji.parser(mapValue.MapIndex(key).Interface(), dimension+1, keyindex)
				//fmt.Printf("reflect.Map count:%d\n", ji.targetlength)
			}

		}
	case reflect.Slice:
		sliceValue := reflect.ValueOf(data)
		for i := 0; i < sliceValue.Len(); i++ {
			//fmt.Printf("sliceValue.len:%d\n", sliceValue.Len())
			//ji.targetlength += sliceValue.Len()
			ji.parser(sliceValue.Index(i).Interface(), dimension+1, i)
			//ji.GetTargetLenth(sliceValue.MapIndex(i).Interface(), true)
			//fmt.Printf("count:%d\n", ji.targetlength)
		}
	}

	return ji.targetlength
}

func (ji *JSONKeyValueIterator) Parser(data interface{}) int {
	ji.Reset(data)
	ji.Copytarget(data)
	return ji.parser(data, 0, 0)
}

func (ji *JSONKeyValueIterator) SetValues(data interface{}, WheretoValue int, value interface{}) []byte {
	ji.setValues(data, WheretoValue, value, 0, 0)
	rawdata, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	return rawdata
	//fmt.Printf("set json result :%s", ji.String())
}

func (ji *JSONKeyValueIterator) setValues(data interface{}, WheretoValue int, value interface{}, dimension int, keyindex int) {
	switch reflect.TypeOf(data).Kind() {
	case reflect.Map:
		// iterate over map keys and set values
		mapValue := reflect.ValueOf(data)
		for _, key := range mapValue.MapKeys() {
			sub := mapValue.MapIndex(key).Interface()
			sub1 := reflect.TypeOf(sub).Kind()
			//ji.SetValues(mapValue.MapIndex(key).Interface(), WheretoValue, value)

			if sub1 != reflect.Slice {
				//ji.index++
				//fmt.Printf("key:%s\n", key.String())
				if ji.storeSort[WheretoValue].dimension == dimension &&
					ji.storeSort[WheretoValue].key == key.String() &&
					ji.storeSort[WheretoValue].keyindex == keyindex {
					//ji.SetValues(mapValue.MapIndex(key).Interface(), WheretoValue, value, false)

					mapValue.SetMapIndex(key, reflect.ValueOf(value))
					return
				} else {
					ji.setValues(mapValue.MapIndex(key).Interface(), WheretoValue, value, dimension, keyindex)
				}
			} else {
				ji.setValues(mapValue.MapIndex(key).Interface(), WheretoValue, value, dimension+1, keyindex)
			}
		}
	case reflect.Slice:
		sliceValue := reflect.ValueOf(data)
		for i := 0; i < sliceValue.Len(); i++ {
			ji.setValues(sliceValue.Index(i).Interface(), WheretoValue, value, dimension+1, i)
		}
	}
}
