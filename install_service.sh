#go build

# 定义要检测的文件名
filename="./glint" 
# 文件名移动到对应的目录,jinkens方便部署
bindir="./bin"
# 插入的对应目录
installDir="/usr/local/863"

# 检测程序
if [ ! -e "$filename" ]; then
  echo "${filename} does not exist"
  exit 1
fi
echo "${filename} exists"


# 检测bin的目录
if [ -d $bindir ]; then
  rm -rf $bindir
  echo "Existing $bindir removed"
fi 

mkdir $bindir
echo "$bindir created"

cp ./server.key $bindir
cp ./server.pem $bindir
cp ./glint.service $bindir
cp ./glint $bindir

systemctl stop glint


chmod +x $bindir/glint
cp $bindir/glint $installDir/bin

chmod +x $bindir/glint.service

cp $bindir/glint.service /etc/systemd/system/glint.service

mkdir $installDir
mkdir $installDir/certific
cp $bindir/server.key $installDir/certific
cp $bindir/server.pem $installDir/certific

#设置服务
systemctl daemon-reload 
systemctl stop glint
systemctl enable glint
systemctl start glint
systemctl status glint
