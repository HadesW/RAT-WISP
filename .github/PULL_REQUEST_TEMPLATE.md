## 变更说明

<!-- 做了什么、为什么这么改；关联 issue：Closes #N -->

## 类型

- [ ] feat　- [ ] fix　- [ ] docs　- [ ] refactor　- [ ] chore　- [ ] test

## 本地自检

- [ ] `gofmt -l server shared agent/agent-go` 无输出
- [ ] 三模块 `go vet ./... && go test ./...` 通过（server / shared/protocol / agent-go）
- [ ] `cd client && npm run lint && npm run build` 通过（lint error = 0）
- [ ] 未提交 `data/`、密钥/token、构建产物；新增大文件（>500KB）已在此说明：____
- [ ] 相关文档（README / docs）已同步
- [ ] 已完成 self review，diff 逐文件过了一遍

## 评审关注点（可选）

<!-- 高风险改动、需要重点看的文件或逻辑 -->
