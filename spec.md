# IdP / Authorization Server Token Exchange 仕様

## 1. 目的

本仕様は、IdP / Authorization Server におけるユーザー認証後の `tenant_access` token 発行、および `tenant_access` token から `event_access` token への OAuth2 Token Exchange を定義する。

本仕様は IdP / Authorization Server の仕様であり、BFF、Browser、フロントエンド、ログイン画面、テナント選択UI、Resource Server の詳細実装は対象外とする。

---

## 2. 適用範囲

### 2.1 扱うもの

```text
- ユーザー認証後の tenant_access token 発行
- tenant_access token の claim
- tenant_access → event_access の Token Exchange
- event_access token の claim
- client 認可
- relation service 参照
- audience 検証
- resource 検証
- scope 検証
- JWT 発行
- JWT 失効方針
- 監査ログ
- エラー方針
```

### 2.2 扱わないもの

```text
- BFF 仕様
- Browser 仕様
- フロントエンド仕様
- ログイン画面
- email 入力後のテナント選択 UI
- tenant_access token の具体的な取得画面フロー
- Resource Server の詳細実装
```

---

## 3. 前提

Authorization Server は REST API　を用いてユーザー認証を行う

認証成功後、Authorization Server は特定 tenant 文脈を持つ `tenant_access` token を JWT access token として発行する。

本仕様では `login` token は定義しない。

本仕様における Token Exchange は、`tenant_access` token を subject token として、`event_access` token を発行する処理のみを対象とする。

---

## 4. token 種別

### 4.1 tenant_access token

`tenant_access` token は、認証済みユーザーに対して発行される、特定 tenant 文脈を持つ JWT access token である。

用途:

```text
- tenant 文脈での API アクセス
- event_access token への Token Exchange の subject_token
```

例:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "backend-api",
  "client_id": "client-123",
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

### 4.2 event_access token

`event_access` token は、`tenant_access` token から Token Exchange により発行される、特定 event 文脈を持つ JWT access token である。

用途:

```text
- 特定 event 文脈での API アクセス
```

例:

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-123",
  "aud": "backend-api",
  "client_id": "client-123",
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

## 5. Token Exchange 遷移ルール

Authorization Server は以下の Token Exchange のみを許可する。

| 交換元 token_use | 発行先 token_use | 許可 |
|---|---|---|
| `tenant_access` | `event_access` | 許可 |

以下は禁止する。

| 交換元 token_use | 発行先 token_use |
|---|---|
| `tenant_access` | `tenant_access` |
| `event_access` | `tenant_access` |
| `event_access` | `event_access` |

`login` token は本仕様では定義しない。

許可されない遷移が要求された場合、Authorization Server は `invalid_grant` を返す。

---

## 6. audience 仕様

`audience` は Resource Server の論理識別子である。

具体的な audience 名は本仕様では固定しない。

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

## 7. client 認可仕様

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

### 7.1 Token Exchange 許可条件

Authorization Server は Token Exchange Request に対して以下を検証する。

```text
- client が認証済みである
- client が confidential client である
- client に token-exchange grant が許可されている
- requested audience が client.allowed_audiences に含まれる
- requested scope が client.allowed_scopes に含まれる
- requested token_use 遷移が client.allowed_token_exchange_transitions に含まれる
```

### 7.2 禁止事項

```text
- public client からの Token Exchange
- 未登録 client からの Token Exchange
- allowed_audiences 外の audience 要求
- allowed_scopes 外の scope 要求
- 許可されていない token_use 遷移
```

---

## 8. 暫定 role / scope 仕様

### 8.1 role

Authorization Server が scope 発行可否の判定に使う暫定 role:

```text
owner
admin
staff
```

`owner` / `staff` は relation service から取得する外部 role である。

`admin` は IdP 内部設定または将来の本番 relation service で扱う可能性がある role であり、現時点の `tolo-relation-stub` からは返却されない。

### 8.2 scope

暫定 scope:

```text
tenant.read
tenant.write
events.read
events.write
```

詳細な scope 設計は後で再検討する。

### 8.3 role → scope 対応表

| role | 許可 scope |
|---|---|
| `owner` | `tenant.read`, `tenant.write`, `events.read`, `events.write` |
| `admin` | `tenant.read`, `tenant.write`, `events.read`, `events.write` |
| `staff` | `tenant.read`, `events.read` |

### 8.4 role の扱い

role は Authorization Server が scope 発行可否を判定するための内部情報である。

role は JWT claim には含めない。

relation service から取得した role は、JWT claim へ転記せず、scope 発行判定の入力としてのみ使う。

---

## 9. relation service 参照仕様

Authorization Server は tenant / event の所属関係、および subject user の role を relation service から取得する。

現時点では `tolo-relation-stub` を暫定 relation service 契約として扱う。

### 9.1 参照 API

Authorization Server は、resource から得た `tenantId` と subject token の `sub` を用いて、以下の API を参照する。

```http
GET /tenants/{tenantId}/users/{userId}
```

`userId` には JWT の `sub` をそのまま使う。

### 9.2 response

relation service は以下の JSON を返す。

```json
{
  "tenant": { "id": "tenant-a", "role": "owner" },
  "user": { "id": "user-123" },
  "events": [
    { "id": "event-1", "role": "staff" }
  ]
}
```

`tenant.role` は、user が対象 tenant に role を持たない場合 `null` である。

`events` は、対象 tenant 配下の event のうち、user が role を持つもののみを含む。該当 event がない場合は空配列である。

relation service が返す外部 role は以下のみとする。

```text
owner
staff
```

### 9.3 relation model 制約

relation service のモデル制約は以下とする。

```text
- 1 user は最大 1 tenant に所属する
- event は必ず 1 tenant に属する
- event role を持つ user は、その event の所属 tenant に tenant role を持つ
- tenant role と event role は独立している
```

例: tenant role が `staff` で event role が `owner` の user は成立する。

### 9.4 relation lookup の扱い

Authorization Server は relation service の結果を以下のように扱う。

```text
- tenant.role == null の場合、subject user は対象 tenant の member ではない
- resource の eventId が events[].id に存在しない場合、subject user は対象 event にアクセスできない
- event_access token の scope 判定には、該当 events[].role を使う
- tenant_access token の scope 判定には、tenant.role を使う
```

relation service が `404` を返した場合、対象 tenant は token 発行対象として扱わない。

relation service への通信失敗、timeout、不正 response、未知 role は、token 発行不可として扱う。

### 9.5 IdP 側の入口制約

`tolo-relation-stub` は ID 値を単純な文字列として扱うが、Authorization Server は本仕様の ID 形式制限を入口で必ず適用する。

Authorization Server は、ID 形式検証に失敗した値を relation service へ問い合わせてはならない。

---

## 10. scope 発行ルール

Authorization Server は、要求された `scope` を暗黙に縮小して発行してはならない。

要求 scope に許可外 scope が含まれる場合、Authorization Server は `invalid_scope` を返す。

### 10.1 tenant_access token 発行時

`tenant_access` token 発行時、Authorization Server は以下を満たす scope のみ発行する。

```text
requested_scope ⊆ client.allowed_scopes
requested_scope ⊆ tenant_role.allowed_scopes
```

`tenant_role` は relation service の `tenant.role` から取得する。`tenant.role == null` の場合、tenant_access token は発行しない。

`admin` を使う場合は、IdP 内部設定または将来の本番 relation service の role mapping により `tenant_role` へ割り当てる。`tolo-relation-stub` の response から `admin` を推定してはならない。

### 10.2 event_access token 発行時

`event_access` token 発行時、Authorization Server は以下を満たす scope のみ発行する。

```text
requested_scope ⊆ client.allowed_scopes
requested_scope ⊆ subject_token.scope
requested_scope ⊆ event_role.allowed_scopes
```

`event_role` は relation service の `events[].role` から取得する。

resource の `eventId` に一致する event が `events` に存在しない場合、event_access token は発行しない。

`admin` を使う場合は、IdP 内部設定または将来の本番 relation service の role mapping により `event_role` へ割り当てる。`tolo-relation-stub` の response から `admin` を推定してはならない。

---

## 11. resource 仕様

### 11.1 採用方針

Token Exchange Request では、対象 event の指定に `resource` パラメータを使用する。

`x_tenant_id` / `x_event_id` は使用しない。

### 11.2 tenant resource

`tenant_access` token の resource は以下の形式とする。

```text
https://api.example.com/tenants/{tenantId}
```

### 11.3 event resource

`event_access` token を要求する場合、Token Exchange Request の `resource` は以下の形式とする。

```text
https://api.example.com/tenants/{tenantId}/events/{eventId}
```

### 11.4 resource 検証

Authorization Server は `resource` について以下を検証する。

```text
- 絶対 URI である
- scheme が https である
- host が許可済みである
- path が許可パターンに一致する
- tenantId / eventId が ID 形式に一致する
- relation service 上で tenant が token 発行対象として扱える
- relation service 上で event が tenant に属している
- relation service 上で subject user が対象 event にアクセス可能である
```

### 11.5 ID 形式

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

## 12. JWT 仕様

### 12.1 token 形式

Access Token はすべて JWT とする。

```text
- Opaque Token は使用しない
- Introspection は使用しない
- Resource Server が JWT を自己検証する
```

### 12.2 共通必須 claim

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

### 12.3 tenant_access token 必須 claim

```text
tenant_id
```

### 12.4 event_access token 必須 claim

```text
tenant_id
event_id
```

### 12.5 JWT に含めない claim

以下の claim は JWT に含めない。

```text
role
tenant_role
event_role
```

---

## 13. Token Exchange Request

### 13.1 event_access token 発行

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={tenant_access_token}
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=backend-api
&resource=https://api.example.com/tenants/tenant-a/events/event-1
&scope=events.read events.write
```

Authorization Server は以下を確認する。

```text
- client が認証済みである
- client が Token Exchange を許可されている
- subject_token が有効である
- subject_token_type が access_token である
- subject_token.token_use == tenant_access
- requested audience が client に許可されている
- requested resource が event resource 形式である
- subject_token.tenant_id == resource の tenantId
- relation service に subject_token.sub と resource の tenantId を問い合わせる
- relation service の tenant.role が null ではない
- resource の eventId が relation service の events[].id に存在する
- requested_scope が subject_token.scope を超えていない
- requested_scope が client / event_role に許可されている
```

---

## 14. event status の扱い

event status に基づく細かい業務判断は Authorization Server の責務ではない。

Authorization Server は、event_access token 発行時に、対象 event が token 発行対象として有効かのみ確認する。

Authorization Server が行ってよい確認:

```text
- relation service 上で event が存在する
- relation service 上で event が tenant に属している
- relation service 上で user が event にアクセス可能である
- event が token 発行自体に不適切な状態ではない
```

Resource Server 側で扱うべき判断:

```text
- draft / open / locked / closed などの業務状態に基づく操作可否
- write 操作が現在可能か
- 参加者追加可能期間か
- イベントが満員か
- その他業務ルール
```

---

## 15. role / permission 変更時の方針

JWT 内の `scope` は発行時点の認可スナップショットである。

Resource Server の主判定は `scope` とする。

role は主に Authorization Server が scope 発行時に使う内部情報である。

### 15.1 write 系 API

`tenant.write` または `events.write` を必要とする API では、Resource Server は DB 上の現在の membership / permission を確認し、token 内の scope が現在も許可可能であることを確認する。

### 15.2 read 系 API

read 系 API は短命 token を基本とする。

ただし、read 権限の即時剥奪が必要な API では、Resource Server は現在の membership / permission を確認する。

---

## 16. 失効方針

JWT のみを使用するため、失効は以下の方針とする。

```text
- access token は短命にする
- すべての JWT に jti を含める
- 強制失効が必要な場合は jti denylist を使う
- denylist の TTL は token の exp までとする
```

### 16.1 token TTL

暫定 TTL:

| token_use | TTL |
|---|---|
| `tenant_access` | 10〜30分 |
| `event_access` | 5〜15分 |

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
relation_lookup_failed
relation_response_invalid
relation_role_unknown
invalid_token_use_transition
token_revoked
```

relation service の `404 tenant not found`、通信失敗、timeout、不正 response、未知 role、membership 不足は、外部レスポンスで詳細を区別しない。

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
relation_lookup_failed
relation_response_invalid
relation_role_unknown
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
  "client_id": "client-123",
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
  "client_id": "client-123",
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
- login token を定義する
- tenant_access → tenant_access の Token Exchange
- event_access → tenant_access の Token Exchange
- event_access → event_access の Token Exchange
- tenant_id を scope に含める
- event_id を scope に含める
- x_tenant_id / x_event_id を使う
- role / tenant_role / event_role を JWT claim に入れる
- scope を暗黙に縮小して発行する
- 複数 audience の access token を発行する
- Opaque Token を使う
- Introspection を使う
- access token 本体をログに出す
- relation service の詳細な失敗理由を外部レスポンスに出す
```

---

## 20. 未確定事項

以下は未確定とし、後続設計で決める。

```text
- 具体的な Resource Server 分割
- 具体的な audience 名
- 詳細な scope 設計
- API path の最終形
- tenant_access token の具体的な発行 API
- ユーザー認証後の tenant 選択フロー
- Resource Server ごとの permission 再確認ポリシー
- jti denylist を常時使うか、強制失効時のみ使うか
- 本番 relation service で `admin` role を扱うか
```

---

## 21. 最終設計まとめ

```text
scope:
  何ができるか

resource:
  どの event に対する token を要求するか

tenant_id claim:
  どの tenant に対して発行された token か

event_id claim:
  どの event に対して発行された token か

role:
  Authorization Server が scope 発行時に使う内部情報
  relation service から取得する role は JWT claim に入れない

relation service:
  tenant / event の所属関係と subject user の role を返す
  現時点の暫定契約は tolo-relation-stub に合わせる

Authorization Server:
  tenant_access token を発行する
  tenant_access token から event_access token を発行する

Resource Server:
  JWT claim, scope, resource, path, DB を使って最終認可する
```
