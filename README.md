# tun2vless

## 编译luajit
下载[LuaJIT](https://github.com/openresty/luajit2/)源代码

- window
 1. 打开“visual studio 命令提示”窗口
 2. 在命令窗口输入“cd /d <path>\src”切到源代码目录下（<path>是你下载的LuaJIT源代码所在的路径）；再输入命令“msvcbuild”开始编译。
   - 修改msvcbuild.bat文件，把/MD改成/MT
   
   
## c语言版本
依赖[mongoose](https://github.com/lgnyy/mongoose),[lwip](https://github.com/heiher/lwip)

命令行：tun2vless -ip xx -route xx -loglevel 3 -tcpsvr tcp://127.0.0.1 -vlurl xx -vlguid xxx> out.log

参数 | 说明
-------- | -----
-name | tun网卡名称
-ip | tun网卡IP
-defroute | 给tun网卡配置默认路由，程序退出时恢复为系统默认路由
-route | 给tun网卡增加路由（可配置多个）
-loglevel | 日志基本（1-ERROR, 2-INFO, 3-DEBUG, 4-VERBOSE）
-tcpsvr | tun与代理之间的通道，格式：tcp://ip[:port]
-vlurl | vless服务器地址
-vlguid | vless的GUID（base64编码）
-socks5 | socks5代理服务地址

- window

 - 存在的问题
  1. 用vs2019打开文件夹（CMakeLists.txt）编译tun_wintun.c报错（ws2ipdef.h）
