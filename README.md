# 心流 · 真实第三方账号 OAuth 关联

这一版已经把原来“点一下直接显示已授权（Mock）”改为真正 OAuth 流程：

1. 前端请求后端生成官方授权地址。
2. 打开百度网盘 / 语雀 / 飞书 / 钉钉官方登录授权页。
3. 平台回调到本项目后端。
4. 后端用 authorization code 换 access token。
5. token 只保存在后端，不写进 HTML / localStorage。
6. 前端收到授权成功消息，显示真实账号名称和“已授权”。
7. 可点击“解除关联”。

## 为什么不能只用 GitHub Pages

GitHub Pages 只能托管静态 HTML，不能安全保存 OAuth Client Secret，也不能安全执行 code -> access token 的交换。因此“真正关联账户”必须有服务端。这个项目可以直接放进 GitHub 仓库，但运行时应部署到 Node.js 主机（Render、Railway、Fly.io、VPS 等），或者把前端放 GitHub Pages、后端单独部署。

## 本地运行

```bash
npm install
cp .env.example .env
# 在 .env 中填写各平台开放应用的 Client ID / Client Secret
npm start
```

然后打开：

```text
http://localhost:8787
```

## 开放平台配置

你必须在每个平台的开发者/开放平台创建自己的应用，并把回调地址设置为：

- 百度：`https://你的后端域名/api/oauth/baidu/callback`
- 语雀：`https://你的后端域名/api/oauth/yuque/callback`
- 飞书：`https://你的后端域名/api/oauth/feishu/callback`
- 钉钉：`https://你的后端域名/api/oauth/dingtalk/callback`

然后将对应 Client ID / Client Secret 写入服务器环境变量。**不要把 Client Secret 写进 index.html 或提交到 GitHub。**

## GitHub Pages + 独立后端

如果前端仍然要部署在 GitHub Pages，可以在 `index.html` 的脚本运行前设置：

```html
<script>
window.IFLOW_OAUTH_API_BASE = 'https://你的-oauth-后端域名';
</script>
```

并在后端 `.env` 中：

```text
APP_ORIGIN=https://你的用户名.github.io
```

## 当前范围

这一版完成的是“真实账户授权关联”。第三方文件列表 / 文件选择 / 导入 PDF 需要在后端继续调用各平台的网盘或文档 API；这部分不能通过仅仅改变按钮状态来伪装完成。

## 安全说明

- 使用带 HMAC 签名且 10 分钟过期的 OAuth `state` 防止伪造回调。
- access token 不返回给浏览器。
- Client Secret 只读取服务器环境变量。
- 本 Demo 为原型，token 当前保存在 Node 进程内存中；服务重启后需要重新授权。生产环境请换成数据库/Redis/KV，并加密持久化 token。
