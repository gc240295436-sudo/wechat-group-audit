# WeChat Group Audit

[![Tests](https://github.com/gc240295436-sudo/wechat-group-audit/actions/workflows/tests.yml/badge.svg)](https://github.com/gc240295436-sudo/wechat-group-audit/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**用完整群成员关系，找出尚未覆盖的微信好友。**

> 好友只要在这几个群中的任意一个，就不用管。把一个群都没进的人列出来。

WeChat Group Audit 按账号身份交叉匹配，输出可查找、可复核、可继续对比的名单。支持 Windows 本机只读采集，也支持跨平台分析明确提供的 JSON 或静态 SQLite 快照。

## 能做什么

- **未覆盖名单**：全部目标群都不在的好友。
- **交集与重复**：任一群、全部群、仅一个群、多个群或完整分布。
- **覆盖与重叠**：各群好友覆盖率、共同成员数及其中好友数。
- **定向查询**：按备注、昵称、微信号或匿名核对 ID 搜索。
- **历史变化**：对比两次结果中的新增、移出及保留人员。
- **分类导出**：普通好友与企业微信联系人分别列出，提供 Markdown、TXT、CSV 和 JSON。

一次支持 1–64 个群。成员匹配使用完整关系表，不依据发言推测，潜水成员也会纳入。本人、公众号、系统账号、已删除记录和非好友群成员不会混入好友结果。

## 先用演示数据试一下

需要 Python 3.12+。JSON／静态 SQLite 分析只依赖标准库；下面的演示无需微信登录或额外加密依赖。

    git clone https://github.com/gc240295436-sudo/wechat-group-audit.git
    cd wechat-group-audit
    python -m pip install -e .

    python -m wechat_group_audit rooms --input examples/directory.json
    python -m wechat_group_audit audit --input examples/directory.json --group "活动通知群" --group "日常交流群" --mode missing

示例中的账号、昵称和成员关系均为合成数据。预期未覆盖 **2 位**，其中普通好友 1 位、企业微信联系人 1 位。终端只显示统计和报告路径，完整名单保存在本机。

## Windows 本机使用

先自行登录需要核对的微信账号。推荐使用独立虚拟环境：

    py -3.12 -m venv .venv
    ./.venv/Scripts/python.exe -m pip install -e ".[live]"

    ./scripts/wga.ps1 sources
    ./scripts/wga.ps1 rooms --source SOURCE_ID --me MY_ACCOUNT --find "群名关键词"
    ./scripts/wga.ps1 audit --source SOURCE_ID --me MY_ACCOUNT --group "活动通知群" --group "日常交流群" --mode missing

MY_ACCOUNT 是本人的 username 或微信号，不能填昵称；SOURCE_ID 从来源列表明确选择。多账号、同名群需要先消歧。迁移目录可用 --data-dir 'D:/WeChatData/所选账号/db_storage' 明确指定。

Windows 路线只读当前用户、签名通过的微信进程及所选账号通讯录，认证每个数据库页并处理已提交 WAL。分析在内存中完成，密钥和明文库不落盘；无需 Frida、调试器、注入或自动提权。扫码登录由用户完成。

**已实测范围**：Windows、AMD64 微信 4.1.7.33、Python 3.12.14。微信更新可能改变内存布局或 Schema，其他版本须单独验证。macOS／Linux 支持离线输入，不提供本机客户端密钥采集。

## 筛选参数

| 参数 | 结果 |
| --- | --- |
| --mode missing | 所有目标群都不在，默认 |
| --mode any | 至少在一个目标群 |
| --mode all | 所有目标群都在 |
| --mode single | 仅在一个目标群 |
| --mode repeated | 在两个或更多目标群 |
| --mode roster | 完整入群分布 |
| --kind personal/enterprise/all | 普通好友、企业微信联系人或全部 |
| --find "备注或昵称" | 缩小好友范围 |
| --expect 406 --expect 122 | 按选群顺序核对预期人数 |
| --previous /private/old/members.json | 对比上次同范围报告 |
| --output /private/results | 指定本地导出根目录 |

完整输入格式与操作示例见 [使用手册](references/usage.md)。

## 报告与隐私

每次运行在本机私密应用数据区创建独立结果目录：

- members.md：名单、群覆盖率与重叠统计。
- members.txt：便于查找和复制的纯文本名单。
- members.csv：可在 Excel 中筛选的表格，潜在公式内容按文本转义。
- members.json：结构化结果，供下次对比。

默认不导出单独的 username／微信号字段，同名及空白昵称保留匿名核对号；确需原始标识时使用 --identifiers。昵称、备注仍可能包含个人信息，报告不等于匿名化数据。结果不上传网络，也不会自动拉群、群发或修改资料。

缺表、缺成员映射、身份不明、同名歧义或人数不符时，程序停止并说明缺口。范围仅限本机已同步记录；名单移出也可能来自删除好友等变化，不能直接认定已经入群。

## 开发

    python -m pip install -e ".[live]"
    python -m unittest discover -s tests -v
    python tools/check_release.py

GitHub Actions 在 Windows 与 Ubuntu 上运行合成测试和发布内容检查。测试不连接真实账号，不包含个人数据库或真实好友名单。实时采集仍应单独验收当前客户端版本。

## 许可证与来源

本项目采用 [MIT License](LICENSE)。主体为独立实现；唯一的源代码引入是直接从 MIT 项目 TANGandXUE/wcdb-key-tool 选取的只读密钥对象遍历辅助函数。其署名、完整许可、固定提交及校验值见 [来源说明](PROVENANCE.md) 和 [LICENSES](LICENSES)。

本项目不包含 yichen-skills 的受限源文件，不依赖其安装目录，也不继承其本地运行环境。
