# glint
glint 是一款golang开发的web漏洞主动(被动)扫描器，是目前为止跟上主流技术的测试工具,如有一下功能:
# 最小golang版本:golang 1.19

1.xss AST语义检测 配合浏览器爬虫污点记录检测会测试特殊xss检测

2.SQL 注入检测 （刚刚完成布尔类型检测，错误型检测，时间型检测，逐渐完善oob反链检测）

3.xray poc 脚本检测（这个偷懒主要参照 https://github.com/jweny/pocassist 
，目前截至2022/10/18日发现，这个随着xray基础函数不断的更新，撤销xray脚本poc解析执行引擎,自己使用更强更健壮的js实现脚本自定义开发)

4.基于浏览器的爬虫主动扫描 

5.被动扫描

6.csrf 检测

7.ssrf 检测 （正在重构）

8.jsonp ast语义检测

9.Xxe 实体注入检测 支持回显和反链平台 （正在重构）

10.CRLF 检测

11.CORS 跨域共享检测

12.应用服务错误检测（主动）

13.SSL版本检测（主动）

14.cmd webshell后门注入检测(刚改成反链webshell)

15.路径穿越检测

16.长密码拒绝服务检测

17.文件上传检测

18.Struts2插件系列检测

### 目前情况
提交频繁，几乎每天都在改动，此项目目前全程一个人开发，研究者比较难以使用
除了以下推荐命令可以使用，其他的设计还得自己花费时间研究

### 粗略的使用说明
因为启动模式设计得很多，比较混乱，我个人推荐研究人员使用主动扫描和被动扫描,记住装上chrome

### 下载golang,并配置好代理,且在当前目录下运行，生成glint.exe|glint
```shell
 go build
```

### 主动扫描
```shell
.\glint.exe  --config config.yaml  --configtype yaml  --cert server.pem --key server.key   http://192.168.166.2/pikachu
```

### 被动扫描
```shell
.\glint.exe  --passiveproxy  --cert server.pem --key server.key --configtype json
```
被动扫描然后访问  http://martian.proxy/authority.cer 下载证书浏览器导入就行

浏览器设置8080代理 (你的局域网ip 如192.168.166.8):8080 ,当然你在agent.go configure 函数中修改

## 待开发

一般逻辑漏洞的ai检测,极具挑战性的研究功能

OOB反链平台的重构

domxss ast检测

此项目还在开发阶段,距离发行版放出要我测试直到满意为止。

## 近期更新
2023/4/10 我最近有两个方向1.在偏研究ai方向，2.自定义js脚本已经在另一个项目完成，发现这个框架似乎有点过时了，最多完善domxss和爬虫，剩下的脚本很多都在js项目上开发，纠结中。