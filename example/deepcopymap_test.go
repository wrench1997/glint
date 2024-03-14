package mydemo

import (
	"fmt"
	"glint/util"
	"testing"
)

func Test_DeepCopy(t *testing.T) {
	original := map[string]interface{}{
		"name": "John",
		"age":  30,
		"address": map[string]interface{}{
			"city":  "New York",
			"state": "NY",
		},
		"interests": []interface{}{
			"reading",
			"swimming",
			"travelling",
		},
	}

	copy := util.DeepCopyMap(original)

	// 修改拷贝后的 map
	copy["name"] = "Alice"
	copy["address"].(map[string]interface{})["city"] = "San Francisco"
	copy["interests"].([]interface{})[0] = "hiking"

	fmt.Println("Original map:", original)
	fmt.Println("Copied map:", copy)

}
