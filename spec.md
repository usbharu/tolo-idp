# OAuth2 マルチテナント・イベント単位 Token Exchange 仕様 改訂版

## 1. 目的

本仕様は、マルチテナント環境において、OAuth2 Token Exchange を用いてアクセストークンの権限範囲を段階的に狭める方式を定義する。

```text
ログイン後 token
  → tenant_access token
  → event_access token
```

`tenant_id` / `event_id` は `scope` には含めず、Token Exchange Request の `resource` パラメータから解釈し、発行後 JWT の claim として表現する。

---

## 2. 基本方針

### 2.1 scope

`scope` は「何ができるか」を表す。

暫定 scope:

```text
tenant.read
tenant.write
events.read
events.write
```

詳細な scope 設計は後で再検討する。

### 2.2 resource

`resource` は「どの tenant / event に対する token を要求するか」を表す。

`x_tenant_id` / `x_event_id` は使用しない。

### 2.3 claim

発行後 JWT には、対象 tenant / event を claim として含める。

```json
{
  "tenant_id": "tenant-a",
  "event_id": "event-1"
}
```

### 2.4 Resource Server

Resource Server は API 実行時の最終認可を行う。

確認対象:

```text
- JWT 署名
- iss
- aud
- exp / nbf
- token_use
- scope
- resource
- tenant_id
- event_id
- path との整合性
- DB 上の現在の permission
- リソース状態
```

---

## 3. 構成要素

```text
Browser
  ↓ Cookie
BFF
  ↓ Token Exchange
Authorization Server
  ↓ JWT Access Token
Resource Server
```

### 3.1 Browser

Browser は access token を直接保持しない。

保持するもの:

```text
- セッション Cookie
```

保持しないもの:

```text
- access token
- refresh token
- tenant_access token
- event_access token
- client secret
```

### 3.2 BFF

BFF は以下を担当する。

```text
- セッション確認
- Token Exchange の実行
- 交換後 token の保存
- Resource Server への API 呼び出し
```

### 3.3 Authorization Server

Authorization Server は以下を担当する。

```text
- Token Exchange エンドポイントの提供
- subject_token の検証
- client 認証
- client ごとの audience / scope 許可判定
- resource の検証
- tenant_id / event_id の解釈
- role に基づく scope 発行可否判定
- token_use 遷移の強制
- JWT access token の発行
- 監査ログの記録
```

Authorization Server は認可判断の一次判定を行うが、Resource Server の最終認可を代替しない。

### 3.4 Resource Server

Resource Server は以下を担当する。

```text
- JWT の自己検証
- scope の確認
- resource / tenant_id / event_id と request path の照合
- DB を用いた現在 permission の確認
- 業務状態に基づく操作可否判定
```

---

## 4. Token Exchange 遷移ルール

Authorization Server は、交換元 token の `token_use` に基づき、以下の Token Exchange のみを許可する。

| 交換元 token_use | 発行先 token_use | 許可 |
|---|---|---|
| `login` | `tenant_access` | 許可 |
| `tenant_access` | `event_access` | 許可 |
| `login` | `event_access` | 禁止 |
| `tenant_access` | `tenant_access` | 禁止 |
| `event_access` | `tenant_access` | 禁止 |
| `event_access` | `event_access` | 禁止 |

許可されない遷移が要求された場合、Authorization Server は `invalid_grant` を返す。

---

## 5. audience 仕様

`audience` は Resource Server の論理識別子である。

現時点では具体的な audience 名は未確定とする。

確定ルール:

```text
- Token Exchange Request では audience を必須とする
- audience は Authorization Server への登録制とする
- client ごとに allowed_audiences を持つ
- 1 access token は 1 audience のみを持つ
- 複数 audience を持つ access token は発行しない
```

要求された `audience` が client に許可されていない場合、Authorization Server は `invalid_target` を返す。

---

## 6. client ごとの Token Exchange 許可設定

Authorization Server は `client_id` ごとに以下の設定を持つ。

```text
client_id
client_type
allowed_grant_types
allowed_token_exchange_transitions
allowed_audiences
allowed_scopes
max_token_ttl_by_token_use
```

### 6.1 必須ルール

```text
- Token Exchange を許可された client のみが Token Exchange を実行できる
- public client からの Token Exchange は禁止する
- confidential client のみ Token Exchange を実行できる
- requested audience は client.allowed_audiences に含まれていなければならない
- requested scope は client.allowed_scopes に含まれていなければならない
- requested token_use 遷移は client.allowed_token_exchange_transitions に含まれていなければならない
```

---

## 7. 暫定 role / scope 仕様

### 7.1 role

暫定 role:

```text
owner
admin
staff
```

### 7.2 scope

暫定 scope:

```text
tenant.read
tenant.write
events.read
events.write
```

### 7.3 role → scope 対応表

| role | 許可 scope |
|---|---|
| `owner` | `tenant.read`, `tenant.write`, `events.read`, `events.write` |
| `admin` | `tenant.read`, `tenant.write`, `events.read`, `events.write` |
| `staff` | `tenant.read`, `events.read` |

### 7.4 注意

この role / scope 対応表は暫定である。

詳細な scope 設計は後で再検討する。

---

## 8. scope 発行ルール

Authorization Server は、要求された `scope` を暗黙に縮小して発行してはならない。

要求 scope に許可外 scope が含まれる場合、`invalid_scope` を返す。

### 8.1 tenant_access token 発行時

```text
requested_scope ⊆ client.allowed_scopes
requested_scope ⊆ role.allowed_scopes
```

### 8.2 event_access token 発行時

```text
requested_scope ⊆ client.allowed_scopes
requested_scope ⊆ subject_token.scope
requested_scope ⊆ role.allowed_scopes
```

---

## 9. resource 仕様

### 9.1 採用方針

Token Exchange Request では、対象 tenant / event の指定に `resource` パラメータを使用する。

`x_tenant_id` / `x_event_id` は使用しない。

### 9.2 tenant resource

tenant token を要求する場合:

```text
resource=https://api.example.com/tenants/{tenantId}
```

### 9.3 event resource

event token を要求する場合:

```text
resource=https://api.example.com/tenants/{tenantId}/events/{eventId}
```

### 9.4 resource 検証

Authorization Server は `resource` について以下を検証する。

```text
- 絶対 URI である
- scheme が https である
- host が許可済みである
- path が許可パターンに一致する
- tenantId / eventId が ID 形式に一致する
- tenant が存在し有効である
- event token の場合、event が tenant に属している
- subject user が対象 tenant / event にアクセス可能である
```

### 9.5 ID 形式

tenantId / eventId は以下の形式に限定する。

```text
^[A-Za-z0-9_-]{1,64}$
```

入力値は以下を行わない。

```text
- trim しない
- 大文字小文字変換しない
- Unicode 正規化しない
```

---

## 10. token 種別

## 10.1 login token

ログイン直後に得られる token。

用途:

```text
- 自分自身の情報取得
- 所属 tenant 一覧取得
- tenant_access token への Token Exchange
```

例:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "bff",
  "client_id": "bff-client",
  "scope": "openid profile tenant.read",
  "token_use": "login",
  "iat": 1710000000,
  "nbf": 1710000000,
  "exp": 1710000300,
  "jti": "jti-login-001"
}
```

## 10.2 tenant_access token

特定 tenant の API 利用に使う token。

例:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "backend-api",
  "client_id": "bff-client",
  "scope": "tenant.read tenant.write events.read events.write",
  "token_use": "tenant_access",
  "resource": "https://api.example.com/tenants/tenant-a",
  "tenant_id": "tenant-a",
  "iat": 1710000000,
  "nbf": 1710000000,
  "exp": 1710000900,
  "jti": "jti-tenant-001"
}
```

## 10.3 event_access token

特定 event の API 利用に使う token。

例:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "backend-api",
  "client_id": "bff-client",
  "scope": "events.read events.write",
  "token_use": "event_access",
  "resource": "https://api.example.com/tenants/tenant-a/events/event-1",
  "tenant_id": "tenant-a",
  "event_id": "event-1",
  "iat": 1710000000,
  "nbf": 1710000000,
  "exp": 1710000600,
  "jti": "jti-event-001"
}
```

---

## 11. JWT 仕様

### 11.1 token 形式

Access Token はすべて JWT とする。

```text
- Opaque Token は使用しない
- Introspection は使用しない
- Resource Server が JWT を自己検証する
```

### 11.2 共通必須 claim

```text
iss
sub
aud
client_id
scope
token_use
resource
iat
nbf
exp
jti
```

### 11.3 tenant_access token 必須 claim

```text
tenant_id
```

### 11.4 event_access token 必須 claim

```text
tenant_id
event_id
```

### 11.5 role claim

以下の claim は JWT に入れない。

```text
role
tenant_role
event_role
```

role は Authorization Server が scope 発行可否を判定するための内部情報であり、Resource Server は role claim に依存してはならない。

---

## 12. Token Exchange Request

### 12.1 tenant_access token 発行

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(bff-client:secret)

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={login_token}
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=backend-api
&resource=https://api.example.com/tenants/tenant-a
&scope=tenant.read events.read
```

Authorization Server は以下を確認する。

```text
- subject_token が有効
- subject_token.token_use == login
- resource が tenant resource 形式である
- user が対象 tenant に現在所属している
- tenant が有効である
- client が Token Exchange を許可されている
- client が audience を要求できる
- requested_scope が client / role に許可されている
```

### 12.2 event_access token 発行

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(bff-client:secret)

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={tenant_access_token}
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=backend-api
&resource=https://api.example.com/tenants/tenant-a/events/event-1
&scope=events.read events.write
```

Authorization Server は以下を確認する。

```text
- subject_token が有効
- subject_token.token_use == tenant_access
- subject_token.tenant_id == resource の tenantId
- resource が event resource 形式である
- event が対象 tenant に属している
- user が event に現在アクセス可能である
- requested_scope が subject_token.scope を超えていない
- requested_scope が client / role に許可されている
```

---

## 13. event status の扱い

event status に基づく細かい業務判断は Authorization Server の責務ではない。

Authorization Server は、event token 発行時に、対象 event が token 発行対象として有効かのみ確認する。

Authorization Server が行ってよい確認:

```text
- event が存在する
- event が tenant に属している
- user が event にアクセス可能である
- event が token 発行自体に不適切な状態ではない
```

Resource Server が行う確認:

```text
- draft / open / locked / closed などの業務状態に基づく操作可否
- write 操作が現在可能か
- 参加者追加可能期間か
- イベントが満員か
- その他業務ルール
```

---

## 14. role / permission 変更時の方針

Resource Server の主判定は `scope` とする。

role は主に Authorization Server が scope 発行時に使う内部情報である。

JWT 内の `scope` は発行時点の認可スナップショットである。

### 14.1 write 系 API

`tenant.write` または `events.write` を必要とする API では、Resource Server は DB 上の現在の membership / permission を確認し、token 内の scope が現在も許可可能であることを確認しなければならない。

### 14.2 read 系 API

read 系 API は短命 token を基本とする。

ただし、read 権限の即時剥奪が必要な API では、Resource Server は現在の membership / permission を確認する。

---

## 15. 失効方針

JWT のみを使用するため、失効は以下の方針とする。

```text
- access token は短命にする
- すべての JWT に jti を含める
- 強制失効が必要な場合は jti denylist を使う
- denylist の TTL は token の exp までとする
```

### 15.1 token TTL

暫定 TTL:

| token_use | TTL |
|---|---|
| `login` | 5〜15分 |
| `tenant_access` | 10〜30分 |
| `event_access` | 5〜15分 |

---

## 16. Resource Server 認可

Resource Server は API 実行時に以下を確認する。

```text
- JWT 署名が有効である
- iss が信頼済みである
- aud が自身の Resource Server 論理識別子と一致する
- exp / nbf が有効である
- token_use が API に対して妥当である
- 必要 scope が含まれている
- token.resource が request path と整合する
- token.tenant_id が request path の tenantId と一致する
- event API の場合、token.event_id が request path の eventId と一致する
- write 系 API の場合、現在 permission を DB で再確認する
- 業務状態に基づき操作可能である
```

---

## 17. エラー方針

外部レスポンスでは、tenant / event / membership の詳細を漏らさない。

### 17.1 Token Exchange が許可されない場合

```json
{
  "error": "invalid_grant",
  "error_description": "The token exchange request is not allowed"
}
```

以下は外部上は同じエラーにまとめる。

```text
tenant_not_found
event_not_found
event_not_in_tenant
user_not_tenant_member
user_not_event_member
invalid_token_use_transition
```

### 17.2 scope が許可されない場合

```json
{
  "error": "invalid_scope",
  "error_description": "The requested scope is not allowed"
}
```

### 17.3 audience / resource が許可されない場合

```json
{
  "error": "invalid_target",
  "error_description": "The requested target is not allowed"
}
```

### 17.4 リクエスト形式が不正な場合

```json
{
  "error": "invalid_request",
  "error_description": "The token exchange request is invalid"
}
```

---

## 18. 監査ログ仕様

Token Exchange は認可境界であるため、成功・失敗の両方を必ず監査ログに記録する。

### 18.1 記録項目

```text
timestamp
request_id
client_id
subject
session_id
source_token_use
requested_token_use
requested_audience
requested_resource
requested_scope
issued_scope
tenant_id
event_id
result
failure_reason
source_ip
user_agent
issued_jti
```

### 18.2 ログに出してはいけないもの

```text
access token 本体
refresh token 本体
client_secret
authorization code
password
```

### 18.3 result

```text
success
failure
```

### 18.4 failure_reason 例

```text
invalid_token_use_transition
client_not_allowed
audience_not_allowed
resource_invalid_format
resource_not_allowed
tenant_not_found
event_not_found
event_not_in_tenant
user_not_tenant_member
user_not_event_member
scope_not_allowed_for_client
scope_not_allowed_for_role
scope_exceeds_subject_token
token_revoked
```

### 18.5 成功ログ例

```json
{
  "timestamp": "2026-05-20T10:00:00Z",
  "request_id": "req-abc",
  "client_id": "bff-client",
  "subject": "user-123",
  "session_id": "sess-abc",
  "source_token_use": "tenant_access",
  "requested_token_use": "event_access",
  "requested_audience": "backend-api",
  "requested_resource": "https://api.example.com/tenants/tenant-a/events/event-1",
  "requested_scope": ["events.read", "events.write"],
  "issued_scope": ["events.read", "events.write"],
  "tenant_id": "tenant-a",
  "event_id": "event-1",
  "result": "success",
  "failure_reason": null,
  "source_ip": "203.0.113.10",
  "user_agent": "Mozilla/5.0 ...",
  "issued_jti": "jti-event-001"
}
```

### 18.6 失敗ログ例

```json
{
  "timestamp": "2026-05-20T10:00:00Z",
  "request_id": "req-def",
  "client_id": "bff-client",
  "subject": "user-123",
  "session_id": "sess-abc",
  "source_token_use": "tenant_access",
  "requested_token_use": "event_access",
  "requested_audience": "backend-api",
  "requested_resource": "https://api.example.com/tenants/tenant-a/events/event-2",
  "requested_scope": ["events.write"],
  "issued_scope": [],
  "tenant_id": "tenant-a",
  "event_id": "event-2",
  "result": "failure",
  "failure_reason": "user_not_event_member",
  "source_ip": "203.0.113.10",
  "user_agent": "Mozilla/5.0 ...",
  "issued_jti": null
}
```

---

## 19. 禁止事項

以下は禁止する。

```text
- Browser に access token を返す
- Browser から直接 Token Exchange する
- tenant_id を scope に含める
- event_id を scope に含める
- x_tenant_id / x_event_id を使う
- role / tenant_role / event_role を JWT claim に入れる
- scope を暗黙に縮小して発行する
- 複数 audience の access token を発行する
- Opaque Token を使う
- Introspection を使う
- Resource Server 側の最終認可を省略する
- access token 本体をログに出す
```

---

## 20. 未確定事項

以下は未確定とし、後続設計で決める。

```text
- 具体的な Resource Server 分割
- 具体的な audience 名
- 詳細な scope 設計
- API path の最終形
- Resource Server ごとの permission 再確認ポリシー
- jti denylist を常時使うか、強制失効時のみ使うか
```

---

## 21. 最終設計まとめ

```text
scope:
  何ができるか

resource:
  どの tenant / event に対する token を要求するか

tenant_id claim:
  どの tenant に対して発行された token か

event_id claim:
  どの event に対して発行された token か

role:
  Authorization Server が scope 発行時に使う内部情報

Authorization Server:
  Token Exchange 時に token を狭める

BFF:
  Token Exchange を実行し、token を保持する

Resource Server:
  JWT claim, scope, resource, path, DB を使って最終認可する
```
