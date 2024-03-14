package mydemo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"glint/config"
	"io/ioutil"
	"os"
	"testing"
)

func Test_Config(t *testing.T) {
	file := "itop_task.json"
	jsonFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	JsonObj := config.TaskJsonConfig{}
	// a := make(map[string]interface{})
	// json.Unmarshal(byteValue, &a)
	d := json.NewDecoder(bytes.NewReader(byteValue))
	d.UseNumber()
	d.Decode(&JsonObj)
	fmt.Println(JsonObj)
}

func Test_Getfild(t *testing.T) {
	file := "itop_task.json"
	jsonFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	tc := config.TaskConfig{}
	// a := make(map[string]interface{})
	// json.Unmarshal(byteValue, &a)
	d := json.NewDecoder(bytes.NewReader(byteValue))
	d.UseNumber()
	d.Decode(&tc.Json)
	v, err := tc.GetValue("qps")

	fmt.Println(v.String())
	// fmt.Println(JsonObj)
}
