# 等待1秒, 避免curl下载脚本的打印与脚本本身的显示冲突, 吃掉了提示用户按回车继续的信息
sleep 1

red='\e[91m'
green='\e[92m'
yellow='\e[93m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'

error() {
    echo -e "\n$red 输入错误! $none\n"
}

warn() {
    echo -e "\n$yellow $1 $none\n"
}

# 本机 IP
InFaces=($(ls /sys/class/net/ | grep -E '^(eth|ens|eno|esp|enp|venet|vif)'))

for i in "${InFaces[@]}"; do  # 从网口循环获取IP
    # 增加超时时间, 以免在某些网络环境下请求IPv6等待太久
    Public_IPv4=$(curl -4s --interface "$i" -m 2 https://www.cloudflare.com/cdn-cgi/trace | grep -oP "ip=\K.*$")
    Public_IPv6=$(curl -6s --interface "$i" -m 2 https://www.cloudflare.com/cdn-cgi/trace | grep -oP "ip=\K.*$")

    if [[ -n "$Public_IPv4" ]]; then  # 检查是否获取到IP地址
        IPv4="$Public_IPv4"
    fi
    if [[ -n "$Public_IPv6" ]]; then  # 检查是否获取到IP地址            
        IPv6="$Public_IPv6"
    fi
done

# 使用纯随机的UUID - 自动生成
uuid=$(cat /proc/sys/kernel/random/uuid)

# 准备工作
apt update
apt install -y curl sudo jq qrencode net-tools lsof

# Xray官方脚本 安装最新版本
echo
echo -e "${yellow}Xray官方脚本安装最新版本$none"
echo "----------------------------------------------------------------"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 更新 geodata
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install-geodata

# 自动生成私钥公钥和ShortID
# 私钥种子
private_key_seed=$(echo -n ${uuid} | md5sum | head -c 32 | base64 -w 0 | tr '+/' '-_' | tr -d '=')

# 生成私钥公钥
tmp_key=$(echo -n ${private_key_seed} | xargs xray x25519 -i)
private_key=$(echo ${tmp_key} | awk '{print $3}')
public_key=$(echo ${tmp_key} | awk '{print $6}')

# ShortID
shortid=$(echo -n ${uuid} | sha1sum | head -c 16)

echo
echo -e "$yellow UUID = $cyan${uuid}${none}"
echo -e "$yellow PrivateKey = ${cyan}${private_key}${none}"
echo -e "$yellow PublicKey = ${cyan}${public_key}${none}"
echo -e "$yellow ShortId = ${cyan}${shortid}${none}"
echo "----------------------------------------------------------------"

# 检查当前BBR状态的函数
check_bbr_status() {
    local tcp_congestion_control=$(sysctl net.ipv4.tcp_congestion_control | awk -F "= " '{print $2}')
    local default_qdisc=$(sysctl net.core.default_qdisc | awk -F "= " '{print $2}')
    
    echo -e "当前系统BBR状态:"
    echo -e "$yellow TCP拥塞控制算法: ${cyan}${tcp_congestion_control}${none}"
    echo -e "$yellow 默认队列调度算法: ${cyan}${default_qdisc}${none}"
    
    if [[ "$tcp_congestion_control" == "bbr" && "$default_qdisc" == "fq" ]]; then
        echo -e "$green BBR已经启用${none}"
        return 0  # BBR已启用
    else
        echo -e "$yellow BBR未完全启用${none}"
        return 1  # BBR未启用
    fi
}

# 打开BBR部分替换为
echo
echo -e "$yellow检查BBR状态$none"
echo "----------------------------------------------------------------"

# 先检查当前BBR状态
check_bbr_status
bbr_status=$?

if [[ $bbr_status -eq 0 ]]; then
    # BBR已启用
    read -p "$(echo -e "BBR已启用，是否仍要重新设置? [${cyan}Y${none}/${cyan}N${none}] (默认: ${cyan}N${none}): ")" reset_bbr
    case "$reset_bbr" in
        [yY][eE][sS] | [yY])
            enable_bbr=true
            ;;
        *)
            enable_bbr=false
            ;;
    esac
else
    # BBR未启用
    read -p "$(echo -e "是否启用BBR以提升网络性能? [${cyan}Y${none}/${cyan}N${none}] (默认: ${cyan}Y${none}): ")" enable_bbr_input
    case "$enable_bbr_input" in
        [nN][oO] | [nN])
            enable_bbr=false
            ;;
        *)
            enable_bbr=true
            ;;
    esac
fi

if [[ "$enable_bbr" = true ]]; then
    echo
    echo -e "$yellow正在启用BBR...${none}"
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control = bbr" >>/etc/sysctl.conf
    echo "net.core.default_qdisc = fq" >>/etc/sysctl.conf
    sysctl -p >/dev/null 2>&1
    echo -e "$green BBR已成功启用${none}"
else
    echo -e "$yellow 保持当前BBR设置不变${none}"
fi
echo "----------------------------------------------------------------"

# 网络栈
echo
echo -e "如果你的小鸡是${magenta}双栈(同时有IPv4和IPv6的IP)${none}，请选择你把Xray搭在哪个'网口'上"
echo "如果你不懂这段话是什么意思, 请直接回车"
read -p "$(echo -e "Input ${cyan}4${none} for IPv4, ${cyan}6${none} for IPv6:") " netstack

if [[ $netstack == "4" ]]; then
  ip=${IPv4}
elif [[ $netstack == "6" ]]; then
  ip=${IPv6}
else
  if [[ -n "$IPv4" ]]; then
    ip=${IPv4}
    netstack=4
  elif [[ -n "$IPv6" ]]; then
    ip=${IPv6}
    netstack=6
  else
    warn "没有获取到公共IP"
  fi
fi

# 端口
default_port=443
while :; do
  read -p "$(echo -e "请输入端口 [${magenta}1-65535${none}] Input port (默认: ${cyan}${default_port}$none):")" port
  [ -z "$port" ] && port=$default_port
  case $port in
  [1-9] | [1-9][0-9] | [1-9][0-9][0-9] | [1-9][0-9][0-9][0-9] | [1-5][0-9][0-9][0-9][0-9] | 6[0-4][0-9][0-9][0-9] | 65[0-4][0-9][0-9] | 655[0-3][0-5])
    echo
    echo
    echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
    echo "----------------------------------------------------------------"
    echo
    break
    ;;
  *)
    error
    ;;
  esac
done

# 目标网站
default_domain="itunes.apple.com"
echo -e "请输入一个 ${magenta}合适的域名${none} Input the domain"
read -p "$(echo -e "(默认: ${cyan}${default_domain}${none}):")" domain
[ -z "$domain" ] && domain=$default_domain

echo
echo
echo -e "$yellow SNI = ${cyan}$domain$none"
echo "----------------------------------------------------------------"
echo

# 配置config.json
echo
echo -e "$yellow 配置 /usr/local/etc/xray/config.json $none"
echo "----------------------------------------------------------------"
cat > /usr/local/etc/xray/config.json <<-EOF
{ // VLESS + Reality
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    // [inbound] 如果你想使用其它翻墙服务端如(HY2或者NaiveProxy)对接v2ray的分流规则, 那么取消下面一段的注释, 并让其它翻墙服务端接到下面这个socks 1080端口
    // {
    //   "listen":"127.0.0.1",
    //   "port":1080,
    //   "protocol":"socks",
    //   "sniffing":{
    //     "enabled":true,
    //     "destOverride":[
    //       "http",
    //       "tls"
    //     ]
    //   },
    //   "settings":{
    //     "auth":"noauth",
    //     "udp":false
    //   }
    // },
    {
      "listen": "0.0.0.0",
      "port": ${port},    // ***
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",    // ***
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${domain}:443",    // ***
          "xver": 0,
          "serverNames": ["${domain}"],    // ***
          "privateKey": "${private_key}",    // ***私钥
          "shortIds": ["${shortid}"]    // ***
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
// [outbound]
{
    "protocol": "freedom",
    "settings": {
        "domainStrategy": "UseIPv4"
    },
    "tag": "force-ipv4"
},
{
    "protocol": "freedom",
    "settings": {
        "domainStrategy": "UseIPv6"
    },
    "tag": "force-ipv6"
},
{
    "protocol": "socks",
    "settings": {
        "servers": [{
            "address": "127.0.0.1",
            "port": 40000 //warp socks5 port
        }]
     },
    "tag": "socks5-warp"
},
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "dns": {
    "servers": [
      "8.8.8.8",
      "1.1.1.1",
      "2001:4860:4860::8888",
      "2606:4700:4700::1111",
      "localhost"
    ]
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
// [routing-rule]
//{
//   "type": "field",
//   "domain": ["geosite:google", "geosite:openai"],  // ***
//   "outboundTag": "force-ipv6"  // force-ipv6 // force-ipv4 // socks5-warp
//},
//{
//   "type": "field",
//   "domain": ["geosite:cn"],  // ***
//   "outboundTag": "force-ipv6"  // force-ipv6 // force-ipv4 // socks5-warp // blocked
//},
//{
//   "type": "field",
//   "ip": ["geoip:cn"],  // ***
//   "outboundTag": "force-ipv6"  // force-ipv6 // force-ipv4 // socks5-warp // blocked
//},
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      }
    ]
  }
}
EOF

# 重启 Xray
echo
echo -e "$yellow重启 Xray$none"
echo "----------------------------------------------------------------"
service xray restart

# 指纹FingerPrint
fingerprint="random"

# SpiderX
spiderx=""

echo "---------- Xray 配置信息 -------------"
echo -e "$green ---提示..这是 VLESS Reality 服务器配置--- $none"
echo -e "$yellow 地址 (Address) = $cyan${ip}$none"
echo -e "$yellow 端口 (Port) = ${cyan}${port}${none}"
echo -e "$yellow 用户ID (User ID / UUID) = $cyan${uuid}$none"
echo -e "$yellow 流控 (Flow) = ${cyan}xtls-rprx-vision${none}"
echo -e "$yellow 加密 (Encryption) = ${cyan}none${none}"
echo -e "$yellow 传输协议 (Network) = ${cyan}tcp$none"
echo -e "$yellow 伪装类型 (header type) = ${cyan}none$none"
echo -e "$yellow 底层传输安全 (TLS) = ${cyan}reality$none"
echo -e "$yellow SNI = ${cyan}${domain}$none"
echo -e "$yellow 指纹 (Fingerprint) = ${cyan}${fingerprint}$none"
echo -e "$yellow 公钥 (PublicKey) = ${cyan}${public_key}$none"
echo -e "$yellow ShortId = ${cyan}${shortid}$none"
echo -e "$yellow SpiderX = ${cyan}${spiderx}$none"
echo

echo "---------- VLESS Reality URL ----------"
if [[ $netstack == "6" ]]; then
  ip=[$ip]
fi
vless_reality_url="vless://${uuid}@${ip}:${port}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${domain}&fp=${fingerprint}&pbk=${public_key}&sid=${shortid}&spx=${spiderx}&#real-$(hostname)"
echo -e "${cyan}${vless_reality_url}${none}"
echo

echo "---------- END -------------"
echo "以上节点信息保存在 ~/_vless_reality_url_ 中"
echo $vless_reality_url > ~/_vless_reality_url_