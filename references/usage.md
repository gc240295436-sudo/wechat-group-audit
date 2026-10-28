# 操作与数据格式

## 选择输入

sources 只读检查当前 Windows 用户的标准 Documents/xwechat_files 目录；迁移后使用 --data-dir。来源有匿名 source 标识和 active_pids。空列表表示未发现微信占用，null 表示检查不可用，不能将未知状态解释为未登录。

rooms 和 audit 必须选择一种输入：

| 参数 | 数据 |
| --- | --- |
| --source SOURCE_ID | 明确授权的 Windows 本机账号 |
| --data-dir PATH | 明确指向所选账号的 db_storage |
| --input FILE.json | 本工具标准关系 JSON |
| --database contact.db | 已解密、静止且完成 checkpoint 的通讯录快照 |

Windows 可用 --pid 明确绑定进程；未指定时须唯一匹配来源文件的占用进程。只请求查询和读取内存权限，要求签名通过且进程属于当前 Windows 用户。--scan-seconds 默认 45，范围 5–180；读取预算 2 GiB、单块最多 2 MiB。失败时不启动调试器、提权或修改保护设置。

SQLite 与实时来源需要 --me。本人 username 优先精确匹配，否则匹配微信号 alias，不通过昵称或修改时间猜本人。标准账号目录还会与解析后本人身份核对。

## 离线 JSON

可运行示例见 [examples/directory.json](../examples/directory.json)：

    {
      "schema": "wga-directory/1",
      "account": "demo-owner",
      "contacts": [
        {"id": "demo-owner", "nickname": "我", "kind": "personal"},
        {"id": "demo-friend", "nickname": "演示好友", "kind": "personal"}
      ],
      "groups": [
        {"id": "demo-group", "name": "演示群", "members": ["demo-owner", "demo-friend"], "complete": true, "member_count": 2}
      ]
    }

- id 是稳定账号身份，不能拿昵称代替；联系人与群 ID 各自必须唯一。
- kind 为 personal、enterprise 或 other，只有前两者进入好友范围。
- complete 默认 true，提供方须实际掌握完整成员；false 时不能生成缺席名单。
- member_count 可选，用于校验声明人数。所有成员须存在于 contacts，陌生群员标为 other。
- JSON 不能证明获取权限或服务器新鲜度，报告会标明其为离线数据。

JSON 最大 32 MiB，联系人最多 20 万，总成员关系最多 200 万。

## 静态 SQLite

需要普通表 contact、chat_room、chatroom_member，以及好友分类和身份字段。好友按 local_type（1/5）、好友 flag、删除和认证状态识别，再排除本人、公众号与保留系统账号。仅存在于群中的陌生人，即使有备注也不是好友。

拒绝仍附有 WAL、SHM 或 rollback journal 的明文副本，不删除 sidecar“修好”输入。以 immutable/query-only 打开，校验完整性，结束时核对源文件元数据。数据库最多 128 MiB。网络/UNC、父目录跳转和软链接/reparse 路径均拒绝。

## 精确选群

rooms 返回的群 ID 是 room- 加摘要。群名做空白与 Unicode 展示规范化后精确匹配，不做模糊猜测。同名群必须用精确 ID。成员缺失、映射未知、重复成员、群名歧义和人数不符均停止分析。

missing 为所有群都不在，any 为任意群，all 为全部群，single 为仅一个群，repeated 为至少两个群，roster 为完整分布。--kind 和 --find 先限定好友范围，再计算结果和各群好友覆盖率；群总成员数不受好友过滤影响。

## 历史对比

    ./scripts/wga.ps1 audit --source SOURCE_ID --me MY_ACCOUNT --group "活动通知群" --group "日常交流群" --mode missing --previous 'C:/Private/old-run/members.json'

只接受同一 wga-report/1 版本、账号、群集合、模式、好友类型和搜索范围的完整报告。稳定 ID 按账号隔离，昵称和 SQLite 行号变化不改变身份。群顺序可以变化；其他工具的 report.json 不能混用。

差异分 added（新增）、removed（移出）、unchanged（保留）。移出不等于已入群，删除好友或分类变化也可能改变结果。

## 输出

Windows 默认 %LOCALAPPDATA%/WeChatGroupAudit/results；其他平台默认 $XDG_DATA_HOME/WeChatGroupAudit/results 或 ~/.local/share/WeChatGroupAudit/results。每次生成独立目录，避免覆盖；Windows 对新目录设置仅当前用户与 SYSTEM 可访问的 ACL，其他平台使用目录 700／文件 600 权限。

--output 可指定其他本地根目录，但不能位于本项目源码或包安装目录内。全部文件写入后回读验证，JSON 完整报告最后写入。TXT/CSV 使用 UTF-8 BOM；CSV 潜在公式字段按文本转义，JSON/TXT 保留原始显示内容。

昵称和备注可能自带联系方式。默认省略结构化账号标识不代表完整匿名化；仅明确需要时使用 --identifiers，不要把个人报告放到公共仓库。
