package mydemo

import (
	"fmt"
	"testing"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

func Test_Functiondiscover(t *testing.T) {
	jsbody := `
	//phpdeserialization.js
	const { CoreLayer, createReport, browerHttpJob } = require('../core/core.js')
	
	
	
	
	
	const php_payload_list = [];
	
	class classPhpDeserialization extends CoreLayer {
		constructor(coreobj) {
			super(coreobj);
		}
	
		async startTesting() {
			if (this.variations.length != 0 && this.method == "POST") {
				for (var i = 0; i < this.variations.length; i++) {
					let report = await this.attack(i);
				}
			}
		}
	
		async attack(index) {
			for (var i = 0; i < php_payload_list.length; i++) {
				const lastJob = new browerHttpJob(this.browser)
				this.variations.setValue(index, php_payload_list[i])
				const payload = this.variations.toString()
				lastJob.url = this.url
				lastJob.method = this.method
				lastJob.headers = this.headers
				lastJob.postData = payload
				lastJob.isEncodeUrl = false
				let response = await lastJob.execute();
				if (response.body) {
					response.body.forEach(element => {
						if (element.indexOf("ab49bdd251591b16da541abad631329c") != -1) {
							if (this.url) {
								const msg = { url: this.url, body: element, payload: payload, vuln: this.getVulnId(__filename), level: "h" } //"rj-020-0001"
								this.alert(createReport(msg));
							}
						}
					});
				}
			}
		}
	}
	module.exports = classPhpDeserialization

	`
	// var params = []string{}
	// var vardiscover bool
	o := js.Options{}
	ast, err := js.Parse(parse.NewInputString(jsbody), o)
	if err != nil {
		panic(err.Error())
	}

	// ast.BlockStmt.String()

	// for _, v := range ast.BlockStmt.VarDecls {
	// 	fmt.Println(v.String())
	// }

	//fmt.Println("Scope:", ast.Scope.String())
	//fmt.Println("Scope Func:", ast.Scope.Func.String())

	fmt.Println("ast block:", ast.String())
	// fmt.Println("js block:", ast.JS())

	//ast.BlockStmt.String()
	// l := js.NewLexer(parse.NewInputString(jsbody))
	// for {
	// 	tt, text := l.Next()
	// 	fmt.Printf("value %v type %v \n", string(text), tt)

	// 	switch tt {
	// 	case js.ErrorToken:
	// 		if l.Err() != io.EOF {
	// 			fmt.Println("Error on line:", l.Err())
	// 		}
	// 		t.Log("ok")
	// 		break
	// 	case js.VarToken:
	// 		vardiscover = true
	// 	case js.StringToken:
	// 		str := string(text)
	// 		if vardiscover {
	// 			params = append(params, str)
	// 		}
	// 		vardiscover = false
	// 	case js.IdentifierToken:
	// 		// fmt.Println("IdentifierToken", string(text))
	// 	}
	// }
}
