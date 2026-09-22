"""内置规则（rules.py）回归测试。

用法（在项目根目录执行，零依赖）：

    .venv/bin/python -m unittest backend.tests.test_rules -v
    # 或
    .venv/bin/python backend/tests/test_rules.py

为什么必须有这个文件
--------------------
规则是正则，改一个字符就可能**同时**「消掉一片误报」和「干掉一个真漏洞」。
前者看得见（报告条数骤降），后者看不见（报告显示"没发现"，没人会来报 bug）。
2026-09-22 那次误报治理就是教训：`path-traversal` 的一条 `\\.\\.[/\\\\]` 分支
在一个 Angular 仓库里刷出 805 条误报（占报告 90%），而修它的过程完全可能顺手
把「真·路径穿越」一起静音。所以每条规则都必须配：

  * 正例 POSITIVE —— 真实漏洞形态，**必须**命中；
  * 反例 NEGATIVE —— 历史上真实出现过的误报样本，**必须**不命中。

加规则 / 改规则时，请同时补两边的用例。只收紧不加反例，等于没有回归。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.core import rules  # noqa: E402


def hits(rule_id: str, path: str, code: str) -> list[dict]:
    """跑一遍规则，返回指定规则在本文件上的命中。"""
    return [h for h in rules.scan_text(path, code) if h["rule_id"] == rule_id]


# ---------------------------------------------------------------- 用例表
# 每项：(说明, 规则 id, 文件相对路径, 代码片段)

POSITIVE: list[tuple[str, str, str, str]] = [
    # ---- 路径穿越：外部输入进入文件系统 API ----
    ("Java 拼接 request 参数读文件", "path-traversal", "src/Download.java",
     'File f = new File(baseDir + request.getParameter("name"));'),
    # 注意：这里刻意写成两行。path-traversal 有**文件级**判据（EXTERNAL_INPUT_HINTS），
    # 只在这个文件真的会收到外部输入时才评判 —— 否则 `ReadFile(fileName)` 这种
    # 工具函数会整片误报。单行夹具也要把「入口」写出来，才代表真实的 Web 文件。
    ("Java Paths.get + 上传文件名", "path-traversal", "src/Up.java",
     '@RequestParam("name") String name;\nFiles.readAllBytes(Paths.get(dir, filename));'),
    ("Python os.path.join 拼 get 参数", "path-traversal", "app/views.py",
     'open(os.path.join(BASE_DIR, request.args.get("file")))'),
    ("Node readFile 取 req.query.path", "path-traversal", "routes/dl.js",
     "fs.readFile(req.query.path, (e, d) => cb(e, d));"),
    ("PHP include 取 $_GET", "path-traversal", "web/index.php",
     "include($_GET['page'] . '.php');"),

    # ---- SQL 注入：真正的 SQL 结构 + 拼接 ----
    ("Java SELECT 拼接", "sql-string-concat", "src/Dao.java",
     'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";'),
    ("Python UPDATE SET 拼接", "sql-string-concat", "app/db.py",
     'cur.execute("UPDATE users SET name = %s" % name)'),
    ("JS 模板串 DELETE FROM", "sql-string-concat", "src/q.js",
     "const sql = `DELETE FROM t WHERE id = ${id}`;"),

    # ---- SSRF：服务端客户端真的发请求 ----
    ("Python requests 取 request 参数", "ssrf", "app/proxy.py",
     'resp = requests.get(request.args.get("url"))'),
    ("Java RestTemplate exchange", "ssrf", "src/Fetch.java",
     '@RequestParam String url;\nResponseEntity<String> r = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);'),
    ("Go http.Get 取 target", "ssrf", "internal/fetch.go",
     'resp, err := http.Get(req.URL.Query().Get("target"))'),

    # ---- 表达式注入：动态执行 ----
    ("JS new Function 拼代码", "expression-injection", "src/util.ts",
     'const f = new Function("return " + code)();'),
    ("Java SpEL 解析器", "expression-injection", "src/Expr.java",
     "SpelExpressionParser parser = new SpelExpressionParser();"),
    ("Java 解析器实例上解析用户表达式", "expression-injection", "src/E.java",
     "Object v = parser.parseExpression(userInput);"),
    ("JS eval 执行响应体", "expression-injection", "src/load.ts",
     "script.innerHTML = eval(res);"),

    # ---- 弱加密：真的在选用弱算法 ----
    ("Java 用 MD5 做摘要", "weak-crypto", "src/Hash.java",
     'MessageDigest md = MessageDigest.getInstance("MD5");'),
    ("Go 用 md5 算摘要", "weak-crypto", "utils/md5util/md5util.go",
     "has := md5.Sum(data)"),
    ("Python hashlib 用 md5", "weak-crypto", "app/sign.py",
     "h = hashlib.md5(token.encode()).hexdigest()"),
    ("AES ECB 模式", "weak-crypto", "src/Aes.java",
     "AES aes = new AES(Mode.ECB, Padding.PKCS5Padding, keyBytes);"),

    # ---- 私钥块：真密钥材料（标记后跟着 base64 正文）----
    ("PEM 私钥文件", "private-key-block", "certs/server.key",
     "-----BEGIN RSA PRIVATE KEY-----\n"
     "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj"),
    ("代码里内嵌单行私钥", "private-key-block", "src/legacy.go",
     'const pemKey = `-----BEGIN RSA PRIVATE KEY-----\n'
     'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjAgMBAAE=`'),

    # ---- 命令执行：拼接了外部输入 ----
    ("Python os.system 拼接", "command-exec", "app/tools.py",
     'os.system("ping -c 1 " + host)'),
    ("Java Runtime.exec 拼接", "command-exec", "src/Cmd.java",
     'Runtime.getRuntime().exec("ping " + host);'),

    # ---- 文件下载：下载名/路径来自请求 ----
    ("Node res.download 取 query", "file-download-path", "routes/dl.js",
     "res.download(path.join(UPLOAD_DIR, req.query.filename));"),
    ("Python send_file 取参数", "file-download-path", "app/dl.py",
     "send_file(os.path.join(BASE, request.args.get('name')))"),

    # ---- 调试模式真的开着 ----
    ("Flask 开启 debug", "debug-enabled", "app/main.py",
     "app.run(host='0.0.0.0', debug=True)"),

    # ---- 不安全随机数：用于安全语义 ----
    ("Java 生成会话号用 Random", "insecure-random", "src/Sess.java",
     'String sessionId = "sess-" + new Random().nextInt(999999);'),
    ("Python 验证码用 random", "insecure-random", "app/otp.py",
     "otp = random.randint(100000, 999999)"),

    # ---- 敏感信息输出 ----
    ("接口返回手机号字段", "sensitive-data-expose", "app/api.py",
     'return {"mobile": user.mobile, "idcard": user.id_card}'),

    # ---- XSS 危险 DOM 写入 ----
    ("业务代码写 innerHTML", "xss-innerhtml", "frontend/render.js",
     "el.innerHTML = userInput;"),

    # ---- 凭证泄漏：测试文件里也不放过 ----
    ("测试文件里硬编码密码", "hardcoded-password", "tests/test_auth.py",
     'password = "RealSecret123"'),
]

NEGATIVE: list[tuple[str, str, str, str]] = [
    # ---- 路径穿越的反例：全是静态相对路径 / 防护代码（修复前 805 条误报的主力）----
    ("TS 相对导入路径", "path-traversal", "src/app.module.ts",
     "import { environment } from '../environments/environment';"),
    ("tsconfig 继承", "path-traversal", "tsconfig.json",
     '"extends": "../tsconfig.json",'),
    ("构建脚本 __dirname 拼接", "path-traversal", "karma.conf.js",
     "dir: require('path').join(__dirname, '../../coverage/'),"),
    ("schematic 静态资源路径", "path-traversal", "tools/index.ts",
     "const collectionPath = path.join(__dirname, '../collection.json');"),
    ("Dockerfile 构建期移动目录", "path-traversal", "Dockerfile",
     "RUN cd /usr/share/nginx/html/dist/ && mv -f * ../"),
    ("路径校验（防线，不是漏洞）", "path-traversal", "src/Guard.java",
     'if (filePath.contains("../")) { throw new SecurityException(); }'),
    ("路径清洗（防线）", "path-traversal", "src/clean.js",
     'const safe = filePath.replace("..", "");'),
    ("XHR 的 open 不是文件 API", "path-traversal", "src/config.ts",
     'xmlhttp.open("GET", filePath, false);'),
    ("Angular 弹窗的 open 不是文件 API", "path-traversal", "src/btn.ts",
     "this.params.modalService.open(this.filterValue).subscribe();"),

    # ---- 路径穿越的反例：变量名不是污点源 ----
    # 下面这几条都来自 2026-09-22 的真实报告（repo4/repo5），
    # 修法：① 变量名（filePath/fileName/query）不再单独作为证据；
    #       ② 文件级判据 —— 这个文件压根不接触外部输入时不评判；
    #       ③ 命令行参数不算信任边界（CLI 调用者本来就能读那个文件）。
    ("Go 工具函数读自己的文件", "path-traversal", "internal/reader/sql/meta.go",
     "data, err := ioutil.ReadFile(filePath)"),
    ("CLI 工具读自己写死的路径", "path-traversal", "xmltest/xmltest.go",
     "bufio.NewReader(os.Stdin).ReadBytes('\\n')\n"
     'fileName, err := filepath.Abs("./digiwin/xmltest/web.config")\n'
     "bytesResult, err := ioutil.ReadFile(fileName)"),
    ("构建脚本里的 argv 不是攻击面", "path-traversal", "themeCssBuild.js",
     "var targetPath = process.argv[2];\nfilename: path.resolve(currentFilePath),"),
    ("库函数里的 fileName 不是污点源", "path-traversal", "internal/queue/disk.go",
     "f, _ := os.OpenFile(path.Join(tmpDir, fileName), os.O_RDWR|os.O_CREATE, 0600)"),
    ("Go 的 Query 类型不是外部输入 query", "path-traversal",
     "internal/windows/perfmon/pdh/pdh_query_windows.go",
     "func (q *Query) Open() error {"),
    ("Go 的 filepath 包名不是 file_path 变量", "path-traversal",
     "utils/fileutil/fileutil_windows.go",
     "return true, filepath.FromSlash(path.Join(val, resultPath[i+1:]))"),

    # ---- SQL 注入的反例：update/delete 只是普通单词 ----
    ("日志文本里的 update/escli", "sql-string-concat", "mgr/api_update.go",
     'return errors.New("[step1][update/escli] err:" + err.Error())'),
    ("字符串里的 update + 变量", "sql-string-concat", "mgr/cluster.go",
     'mgrType := "update runner " + configName'),
    ("WMI 查询不是 SQL", "sql-string-concat", "smartinfotest/smartinfotest.go",
     'QueryWmiByNamespace("\\\\root\\\\wmi", "Select * from MSStorageDriver_FailurePredictThresholds'
     ' Where InstanceName=\'"+currentInstanceName+"\'")'),
    ("单测里的 SQL 夹具", "sql-string-concat", "reader/mysql/mysql_test.go",
     '"mysql_sql":            "select * from " + tablename,'),
    ("单测里的 INSERT 夹具", "sql-string-concat", "reader/postgres/postgres_test.go",
     'rows, err := db.Query("SELECT COUNT(*) FROM " + tabname)'),

    # ---- SSRF 的反例 ----
    ("日志里的 HttpClient 字样", "ssrf", "src/HttpClient.java",
     'log.info("[HttpClient] POST {} - headers: {}, body: {}", url, headers, JSONObject.toJSONString(request));'),
    ("统一封装类里的 url 是方法参数", "ssrf", "src/common/http/HttpClient.java",
     "T response = restTemplate.postForObject(url, httpEntity, responseType);"),
    ("Angular 前端 http.post", "ssrf", "src/repo.ts",
     "return this.http.post('showcase/demo1/getAsisList', params);"),
    ("浏览器 fetch 不是 SSRF", "ssrf", "src/utils/index.ts",
     "const response = await fetch(url);"),
    ("axios 前端请求不是 SSRF", "ssrf", "src/api.js",
     "axios.get('/api/user', { params });"),

    # ---- 表达式注入的反例：别的语言里叫 xxxFunction / parseExpression 的普通函数 ----
    ("Go 的 XxxFunction 定义", "expression-injection", "search_funcs.go",
     "func NewExponentialDecayFunction() *ExponentialDecayFunction {"),
    ("Go 的 GaussDecayFunction", "expression-injection", "search_funcs.go",
     "func NewGaussDecayFunction() *GaussDecayFunction {"),
    ("Go 的 parseExpression 定义", "expression-injection",
     "github.com/olivere/elastic/uritemplates/uritemplates.go",
     "func parseExpression(expression string) (result templatePart, err error) {"),
    ("本地同名函数调用（URI 模板解析器）", "expression-injection",
     "github.com/olivere/elastic/uritemplates/uritemplates.go",
     "template.parts[i*2-1], err = parseExpression(expression)"),

    # ---- 弱加密的反例：导入包 / 协议名常量 / 下拉枚举都不是「在用弱算法」----
    ("Go 导入 crypto/des", "weak-crypto", "utils/crypt/descrypt/descrypt.go",
     '"crypto/des"'),
    ("SNMP 协议名常量", "weak-crypto", "reader/config/models.go",
     'SnmpReaderAuthProtocolMd5          = "MD5"'),
    ("配置项下拉枚举", "weak-crypto", "reader/config/config.go",
     'ChooseOptions: []interface{}{"", "SHA1", "SSHA1", "SHA256", "SSHA256", "SHA384", "SHA512"},'),
    ("SNMP 隐私协议常量", "weak-crypto", "reader/snmp/snmp.go",
     'PrivProtocol string // "DES", "AES", "", 默认: ""'),
    ("自封装的哈希工具不算弱算法调用", "weak-crypto", "transforms/group.go",
     "key = md5util.GetMd5(key)"),
    ("nginx 禁用 MD5/DES", "weak-crypto", "conf/nginx.conf",
     "ssl_ciphers HIGH:!aNULL:!MD5:!DES;"),
    ("openssl 关闭 RC4", "weak-crypto", "conf/openssl.cnf",
     "openssl_ciphers HIGH:!RC4;"),

    # ---- 硬编码凭证的反例：占位符 / 默认值 ----
    ("字段默认值不是真凭据", "hardcoded-password", "utils/models/models.go",
     'Password    = "password"'),
    ("占位符 secret", "hardcoded-password", "conf/app.yml",
     'secret: "changeme"'),

    # ---- 私钥的反例：文档在描述密钥格式，不是真的泄漏 ----
    ("注释里说明 PKCS#1 格式", "private-key-block",
     "utils/crypt/rsacrypt/uiflowdec/ui_flow_dec.go",
     "// 嘗試以 PKCS#1 格式解析 (通常以 -----BEGIN RSA PRIVATE KEY----- 開頭)\n"
     "if priv, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {"),
    ("注释里说明 PKCS#8 格式", "private-key-block",
     "utils/crypt/rsacrypt/uiflowdec/ui_flow_dec.go",
     "// 嘗試以 PKCS#8 格式解析 (通常以 -----BEGIN PRIVATE KEY----- 開頭)\n"
     "if priv, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {"),

    # ---- 命令执行的反例：纯静态、无插值的命令 ----
    ("打包脚本里的静态命令", "command-exec", "pack/compiled.py",
     "os.popen('go build -o aiopskit.exe aiopskit.go')"),

    # ---- 文件下载的反例：日志行里的变量名不是下载路径 ----
    ("日志里的 readFileNum / d.name", "file-download-path", "queue/disk.go",
     'log.Errorf("ERROR: diskqueue(%s) continue fail read, set readFileNum with'
     ' writeFileNum: %d", d.name, d.writeFileNum)'),
    ("日志里的 fname", "file-download-path", "mgr/api_log.go",
     'log.Errorf("log %s fname readFile close error: %v", fname, closeErr)'),
    ("组件方法 onDownload(file) 不是下载路径可控", "file-download-path",
     "image-viewer-list-item.component.ts",
     "this.onDownload(file).subscribe();"),

    # ---- 调试模式的反例：URL 查询串里的 debug=1 ----
    ("pprof 链接里的 debug=1", "debug-enabled", "web/pprofhtml/index_html.go",
     'link := &url.URL{Path: profile.Href, RawQuery: "debug=1"}'),

    # ---- 不安全随机数的反例：UI 随机 ----
    ("随机取正负号", "insecure-random", "src/list.ts",
     "const plusOrMinus = Math.random() < 0.5 ? -1 : 1;"),
    ("随机演示日期", "insecure-random", "src/demo.ts",
     "const d = new Date(+new Date() + Math.floor(Math.random() * 50) * 86400000);"),

    # ---- 敏感信息的反例 ----
    ("测试夹具里的手机号", "sensitive-data-expose", "src/svc.ts",
     "telephone: '11111111111',"),
    ("表单读值不是输出", "sensitive-data-expose", "src/acc.ts",
     "const telephone = this.accountInfoForm.get('telephone');"),
    ("属性比较不是输出", "sensitive-data-expose", "src/acc.ts",
     "if (userInfo.hasOwnProperty('telephone') && userInfo.telephone === control.value) {"),
    ("switch 分支标签", "sensitive-data-expose", "src/dap.ts",
     "case 'telephone': // 入参是 {telephone: value}"),
    ("ua-parser 的枚举常量", "sensitive-data-expose", "ua-parser.js",
     "MOBILE  : MOBILE,"),
    ("注释里的字段说明", "sensitive-data-expose", "src/form.ts",
     "formVerifyType: 'full' // mobilephone: 手機號, 預設: full."),

    # ---- XSS 的反例：测试文件里的夹具 ----
    ("spec 测试里的 document.write", "xss-innerhtml", "src/viewer.spec.ts",
     "document.write('<div class=\"viewerContainer\">Hello World!</div>');"),
    ("Angular 老式 _spec 命名", "xss-innerhtml", "src/viewer_spec.ts",
     "document.write('<div>hi</div>');"),
    ("__tests__ 目录", "xss-innerhtml", "src/__tests__/render.js",
     "document.write('<p>x</p>');"),
]


class RuleRegressionTest(unittest.TestCase):
    def test_all_rules_compiled(self):
        """所有规则的正则都要能编译（写错的正则会被静默跳过）。"""
        self.assertEqual(
            len(rules._COMPILED), len(rules.RULES),
            "有规则的正在则编译失败，检查启动时的 [rules] 报错",
        )

    def test_positive_cases_must_hit(self):
        """正例：真实漏洞形态必须命中，否则就是漏报。"""
        for name, rid, path, code in POSITIVE:
            with self.subTest(case=name, rule=rid):
                self.assertTrue(
                    hits(rid, path, code),
                    f"正例未命中（可能收紧过头，变成漏报）：{name}\n  {code}",
                )

    def test_negative_cases_must_not_hit(self):
        """反例：历史误报样本必须不命中，否则噪声又回来了。"""
        for name, rid, path, code in NEGATIVE:
            with self.subTest(case=name, rule=rid):
                got = hits(rid, path, code)
                self.assertFalse(
                    got,
                    f"反例误报（噪声回归）：{name}\n  {code}\n  实际命中：{got}",
                )

    def test_severity_downgrade(self):
        """severity_downgrade：形态成立但危险性更低时降一级，而不是整条丢掉。"""
        # 拼的是表名（无法用占位符绑定、通常来自内部配置）→ critical 降 high
        for code, path in (
            ('sqls += "Select * From " + tableName + ";"', "reader/sqlite/sqlite.go"),
            ('sqls += "Select * From `" + table + "`;"', "reader/mysql/mysql.go"),
            ('rows, err := db.Query("SELECT COUNT(*) FROM " + tabname)', "reader/sql.go"),
        ):
            got = hits("sql-string-concat", path, code)
            with self.subTest(code=code):
                self.assertTrue(got, f"应当命中（只是要降级）：{code}")
                self.assertEqual(got[0]["severity"], "high", f"表名拼接应降为 high：{code}")
                self.assertEqual(got[0]["confidence"], "low", f"降级同时压低置信度：{code}")

        # 拼的是**条件**（真·SQL 注入）→ 必须保持 critical
        got = hits("sql-string-concat", "src/Dao.java",
                   'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";')
        self.assertTrue(got)
        self.assertEqual(got[0]["severity"], "critical", "条件拼接不能被降级")
        self.assertNotEqual(got[0]["confidence"], "low", "条件拼接仍是中/高置信")


if __name__ == "__main__":
    unittest.main(verbosity=2)
