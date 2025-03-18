渗透测试人员可以通过此BOF，将非托管 Windows可执行文件加载到Beacon内存中并执行它们，检索输出并将其呈现在 Beacon 控制台中。

![image](https://github.com/user-attachments/assets/bfb0adf0-c158-4eea-8514-f7920c5cada2)

完善：
- 需要完善资源释放的结构
- 将此项目分成PEload与PErun
- 加载本地项目选项中添加解密模块
- 分配权限RW->RX

致谢：

这是一个非Hollowing的PE加载器的项目，Octoberfest7的项目在很多细节方便做的很出色。
https://github.com/Octoberfest7/Inline-Execute-PE/
