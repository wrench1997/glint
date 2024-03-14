package crawler

import (
	"net/url"
	"strings"

	"github.com/google/uuid"
)

type Node struct {
	Domain       string `json:"domain"`
	ParentNodeID string `json:"parent_node_id"`
	NodeID       string `json:"nodeid"`
	Name         string `json:"name"`
	Uuid         string `json:"uuid"`
	UrlPath      string `json:"url_path"`
	Url          string `json:"Url"`
	HostID       int64  `json:"host_id"` //给这个站点编号ID
	// NameID   int64
	Children []Node `json:"children"`
}

type SiteRootNode struct {
	root   []Node
	DUTS   []DatabeseUrlTree
	TaskId int64
	HostID int64
}

type DirUrl struct {
	Domain string
	Name   string
	Uuid   string
	//Index  int
}

// 以数据库的形式存储库，并不以树状结构顺序存储，但保留父节点的ID和当前节点ID
type DatabeseUrlTree struct {
	TaskId        int64  `db:"task_id"`
	HostId        int64  `db:"host_id"`
	Url           string `db:"url"`
	CurrentNodeId string `db:"current_node_id"`
	ParentNodeId  string `db:"parent_node_id"`
}

// http://www.uni-president.com.cn/admin/login.asp
func AddToTree(root []Node, DirUrl []DirUrl) []Node {
	if len(DirUrl) > 0 {
		var i int
		for i = 0; i < len(root); i++ {
			if root[i].Name == DirUrl[0].Name { //already in tree
				break
			}
		}
		if i == len(root) {
			id := uuid.New()
			// NodeID := util.RandLetterNumbers(10)
			root = append(root, Node{Domain: DirUrl[0].Domain, Name: DirUrl[0].Name, NodeID: id.String(), Uuid: DirUrl[0].Uuid})
		}
		root[i].Children = AddToTree(root[i].Children, DirUrl[1:])
	}
	return root
}

// SetParentNodeInfo 根据当前节点设置每个节点的父路径。
func SetParentNodeInfo(root []Node) {
	var i int
	if len(root) != 0 {
		for i = 0; i < len(root); i++ {
			for idx, v := range root[i].Children {
				v.ParentNodeID = root[i].NodeID
				v.UrlPath = root[i].UrlPath + "/" + v.Name
				v.Url = root[i].Domain + v.UrlPath
				root[i].Children[idx] = v
			}
		}
		SetParentNodeInfo(root[i-1].Children)
	}
}

// // SetParentNodeId 根据当前节点设置每个节点的URL.
// func SetCurrntUrl(root []Node) {
// 	// var dt DatabeseUrlTree
// 	var i int
// 	if len(root) != 0 {
// 		for i = 0; i < len(root); i++ {
// 			for idx, v := range root[i].Children {
// 				v.ParentNodeID = root[i].NodeID
// 				v.UrlPath = root[i].UrlPath + "/" + v.Name
// 				root[i].Children[idx] = v
// 			}
// 		}
// 		SetParentNodeId(root[i-1].Children)
// 	}
// }

func (r *SiteRootNode) Root() []Node {
	return r.root
}

func (r *SiteRootNode) ADD_NODE(URl string) error {
	var DU []DirUrl
	uu, err := url.Parse(URl)
	if err != nil {
		return err
	}

	Pathss := strings.Split(uu.Path, "/")
	for _, p := range Pathss {
		id := uuid.New()
		DU = append(DU, DirUrl{Name: p, Uuid: id.String(), Domain: uu.Scheme + `://` + uu.Host})
	}

	r.root = AddToTree(r.root, DU)
	SetParentNodeInfo(r.root)
	return nil
}

func (r *SiteRootNode) RootNodetoDBinfo(root []Node) []DatabeseUrlTree {
	var i int

	if len(root) != 0 {
		for i = 0; i < len(root); i++ {
			for _, v := range root[i].Children {
				var dut DatabeseUrlTree
				dut.CurrentNodeId = v.NodeID
				dut.ParentNodeId = v.ParentNodeID
				dut.Url = v.Url
				dut.TaskId = r.TaskId
				dut.HostId = r.HostID
				r.DUTS = append(r.DUTS, dut)
			}
		}
		r.RootNodetoDBinfo(root[i-1].Children)
	}
	return r.DUTS
}

// CanonicalizePath 整合路径 去除../等
func CanonicalizePath() {
	//

}
