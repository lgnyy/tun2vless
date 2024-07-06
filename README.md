# tun2vless

## 编译luajit
下载[LuaJIT](https://github.com/openresty/luajit2/)源代码

- window
 1. 打开“visual studio 命令提示”窗口
 2. 在命令窗口输入“cd /d <path>\src”切到源代码目录下（<path>是你下载的LuaJIT源代码所在的路径）；再输入命令“msvcbuild”开始编译。
   - 修改msvcbuild.bat文件，把/MD改成/MT
   
   
## c语言版本
依赖[mongoose]
命令行：tun2vless -ip 10.0.6.7 -route 110.242.68.66 -loglevel 4 -tcpsvr tcp://127.0.0.1:55551 -vlurl xx -vlguid xxx > out.log
	参数：-vlguid 为base64编码

- window
 - 存在的问题
  1. 用vs2019打开文件夹（CMakeLists.txt）编译tun_wintun.c报错（ws2ipdef.h）
  2. wintun有丢包现象（调用WintunSendPacket成功，到会收到一个丢包的ack）导致卡死；增加简单重发机制，没解决卡死问题；难道要引入tcp协议（如lwip）