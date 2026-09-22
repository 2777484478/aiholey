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
    ("Java Paths.get + 上传文件名", "path-traversal", "src/Up.java",
     "Files.readAllBytes(Paths.get(dir, filename));"),
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
     "ResponseEntity<String> r = restTemplate.exchange(url, HttpMethod.GET, entity, String.class);"),
    ("Go http.Get 取 target", "ssrf", "internal/fetch.go",
     'resp, err := http.Get(req.URL.Query().Get("target"))'),

    # ---- 表达式注入：动态执行 ----
    ("JS new Function 拼代码", "expression-injection", "src/util.ts",
     'const f = new Function("return " + code)();'),
    ("Java SpEL 解析器", "expression-injection", "src/Expr.java",
     "SpelExpressionParser parser = new SpelExpressionParser();"),
    ("JS eval 执行响应体", "expression-injection", "src/load.ts",
     "script.innerHTML = eval(res);"),

    # ---- 弱加密：真的在选用弱算法 ----
    ("Java 用 MD5 做摘要", "weak-crypto", "src/Hash.java",
     'MessageDigest md = MessageDigest.getInstance("MD5");'),
    ("AES ECB 模式", "weak-crypto", "src/Aes.java",
     "AES aes = new AES(Mode.ECB, Padding.PKCS5Padding, keyBytes);"),

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

    # ---- SQL 注入的反例：update/delete 只是普通单词 ----
    ("日志文本里的 update/escli", "sql-string-concat", "mgr/api_update.go",
     'return errors.New("[step1][update/escli] err:" + err.Error())'),
    ("字符串里的 update + 变量", "sql-string-concat", "mgr/cluster.go",
     'mgrType := "update runner " + configName'),

    # ---- SSRF 的反例 ----
    ("日志里的 HttpClient 字样", "ssrf", "src/HttpClient.java",
     'log.info("[HttpClient] POST {} - headers: {}, body: {}", url, headers, JSONObject.toJSONString(request));'),
    ("Angular 前端 http.post", "ssrf", "src/repo.ts",
     "return this.http.post('showcase/demo1/getAsisList', params);"),
    ("浏览器 fetch 不是 SSRF", "ssrf", "src/utils/index.ts",
     "const response = await fetch(url);"),
    ("axios 前端请求不是 SSRF", "ssrf", "src/api.js",
     "axios.get('/api/user', { params });"),

    # ---- 表达式注入的反例：别的语言里叫 xxxFunction 的普通函数 ----
    ("Go 的 XxxFunction 定义", "expression-injection", "search_funcs.go",
     "func NewExponentialDecayFunction() *ExponentialDecayFunction {"),
    ("Go 的 GaussDecayFunction", "expression-injection", "search_funcs.go",
     "func NewGaussDecayFunction() *GaussDecayFunction {"),

    # ---- 弱加密的反例：配置里显式禁用弱算法 ----
    ("nginx 禁用 MD5/DES", "weak-crypto", "conf/nginx.conf",
     "ssl_ciphers HIGH:!aNULL:!MD5:!DES;"),
    ("openssl 关闭 RC4", "weak-crypto", "conf/openssl.cnf",
     "openssl_ciphers HIGH:!RC4;"),

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
