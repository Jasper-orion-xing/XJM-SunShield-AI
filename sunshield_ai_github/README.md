# 欣盾AI（SunShield AI）

企业 AI 安全上传门卫：员工把资料交给 AI 之前，先做本地敏感信息识别、风险解释、人工确认、脱敏、模型分流建议和安全凭证留痕。

## 一键部署到 Streamlit Cloud

1. 将本文件夹上传到一个新的 GitHub 仓库。
2. 打开 Streamlit Cloud，选择该 GitHub 仓库。
3. Main file path 填写：

```text
streamlit_app.py
```

4. 等待依赖安装完成后即可在浏览器中使用。

## 本地运行

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

## 当前能力

- 文本粘贴与 TXT / DOCX / XLSX / 文本型 PDF 上传解析
- 本地识别手机号、邮箱、身份证、银行卡、金额、项目编号、产品型号、内部域名、内部链接、Token、API Key、Secret 等风险项
- 根据目标平台输出低 / 中 / 高 / 严重四级风险
- 支持保留、删除、遮盖、标签替换、哈希、泛化等人工确认动作
- 生成脱敏文本、DOCX / XLSX 脱敏副本、风险报告和安全凭证
- 使用本地 SQLite 保存扫描历史，不在凭证中保存原始敏感正文

## 目录结构

```text
.
├── streamlit_app.py
├── requirements.txt
├── runtime.txt
├── backend/
│   └── app/services/
├── config/
└── sample_data/
```

## 说明

演示文件和词库均为虚构数据，不包含真实客户资料或真实密钥。PDF 当前主要支持文本型 PDF；扫描件 OCR 和坐标级 PDF 红框脱敏属于后续扩展能力。
