package com.demo;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;

/**
 * 示例：故意包含多处安全漏洞，用于演示 Aiholey 扫描能力。
 * 请勿在生产代码中模仿。
 */
public class UserController {

    // 漏洞1：硬编码数据库凭证
    private static final String DB_PASSWORD = "Passw0rd@2024!";
    private static final String DB_URL = "jdbc:mysql://10.0.0.12:3306/demo?user=root&password=Root123456";

    /**
     * 漏洞2：SQL 注入 —— 直接拼接用户输入
     */
    public ResultSet queryUser(Connection conn, String username) throws Exception {
        String sql = "SELECT * FROM users WHERE name = '" + username + "'";
        Statement st = conn.createStatement();
        return st.executeQuery(sql);
    }

    /**
     * 漏洞3：命令注入 —— 拼接参数执行系统命令
     */
    public String ping(String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return new String(p.getInputStream().readAllBytes());
    }

    /**
     * 漏洞4：路径穿越 —— 未校验的下载路径
     */
    public byte[] download(String filename) throws Exception {
        java.io.File f = new java.io.File("/data/reports/" + filename);
        return java.nio.file.Files.readAllBytes(f.toPath());
    }

    /**
     * 漏洞5：弱哈希算法
     */
    public String hashPassword(String raw) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(raw.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * 漏洞6：不安全的反序列化
     */
    public Object deserialize(byte[] data) throws Exception {
        java.io.ObjectInputStream ois =
                new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(data));
        return ois.readObject();
    }

    /**
     * 漏洞7：日志注入 —— 用户输入直接进日志
     */
    public void login(String user, String token) {
        System.out.println("user login: " + user + " token=" + token);
    }
}
