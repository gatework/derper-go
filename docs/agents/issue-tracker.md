# Issue tracker: GitHub

本仓库的 Issue、规格和任务均保存在 https://github.com/gatework/derper-go 的 GitHub Issues，使用 gh CLI 操作。

## 操作约定

- 操作前通过 git remote get-url origin 与 gh repo view --json nameWithOwner 核对目标为 gatework/derper-go；写操作显式指定 --repo gatework/derper-go。不得向技能来源仓库 mattpocock/skills 发布项目工单。
- 创建：gh issue create --repo gatework/derper-go --title "标题" --body-file /path/to/body.md。多行正文先写临时文件，再传 --body-file。
- 读取：gh issue view NUMBER --repo gatework/derper-go --json number,title,body,labels,comments。
- 列表：gh issue list --repo gatework/derper-go --state open --json number,title,body,labels,comments，按实际标签与状态过滤。
- 评论使用 gh issue comment NUMBER --repo gatework/derper-go --body-file FILE；标签使用 gh issue edit NUMBER --repo gatework/derper-go --add-label NAME / --remove-label NAME。
- 关闭前先发表说明，再 gh issue close NUMBER --repo gatework/derper-go；已关闭的 Issue 使用单独评论命令，避免关闭操作吞掉说明。
- 仅在用户明确要求或显式调用的技能流程中创建、评论、修改或关闭工单；初始化不创建业务 Issue。

## 父子任务与阻塞关系

优先使用 GitHub 原生 sub-issue 和依赖。gh 2.94+ 支持 --parent、--add-sub-issue、--blocked-by、--add-blocked-by；旧版本使用 gh api 的 sub_issues 和 dependencies/blocked_by 接口，参数为 Issue 数据库 id，而非 #number 或 node_id。

不支持原生关系时，子任务正文顶部写 Part of #PARENT 与 Blocked by: #N；父任务维护清单。全部阻塞项关闭后任务才可开始。查询阻塞时优先 issue_dependencies_summary.blocked_by；使用 blockedBy 列表时过滤关闭项。

技能要求“发布到 issue tracker”时创建本仓库 Issue；要求“获取工单”时按上述读取。

## Pull requests as a triage surface

PRs as a request surface: no.

本仓库不默认将外部 PR 作为需求分流队列。GitHub 的 Issue 与 PR 共用编号；必要时通过 gh pr view 与 gh issue view 区分。

## Wayfinding

/wayfinder 的 map 为带 wayfinder:map 标签的 Issue；child 为 sub-issue，类型标签为 wayfinder:research、wayfinder:prototype、wayfinder:grilling 或 wayfinder:task。领取前核对未分配、无未关闭阻塞项；领取时分配给实际执行者。解决后发表评论、关闭子任务，并更新 map 的决策与上下文指针。按实际使用创建 wayfinder 标签，本次初始化只补齐五个 triage 标签。
