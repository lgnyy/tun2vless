# tun2vless

## 编译luajit
下载[LuaJIT](https://github.com/openresty/luajit2/)源代码

- window
 1. 打开“visual studio 命令提示”窗口
 2. 在命令窗口输入“cd /d <path>\src”切到源代码目录下（<path>是你下载的LuaJIT源代码所在的路径）；再输入命令“msvcbuild”开始编译。
   - 修改msvcbuild.bat文件，把/MD改成/MT