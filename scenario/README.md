# シナリオテスト (runn)

[runn](https://github.com/k1LoW/runn) の runbook で、HTTP レベルのシナリオテストを行う。
実行は Docker (Compose の `scenario` profile) 経由を前提とする。

## 前提とする配置

| 役割 | ホスト | 備考 |
|---|---|---|
| IdP (tolo-idp) | `localhost:18080` | `docker-compose.dev.yaml` の `app`。issuer も同じ値。現時点ではドメインは意識しない |
| ログインページ | IdP と同一オリジン | 開発中のため同一オリジンで提供する。将来は `example.com` などへ分離する |
| RP | 任意 | Discovery 文書から endpoint を解決する。seed client `client-123` の `redirect_uri` を使う |

Compose 内の runn コンテナからは `localhost` が自分自身を指すため、`--host-rules "localhost app:8080"` で
`localhost:18080` への接続を `app` へ向けている (Host ヘッダは issuer どおり `localhost:18080` のまま)。
これにより Discovery 文書が広告する URL をそのまま使える。

ログインページを別ドメインへ分離するときは、`/api/login` の前に CORS preflight (`OPTIONS`) の step を追加し、
`Origin` を分離先のオリジンにして `Access-Control-Allow-Origin` / `Allow-Credentials` の検証を戻す。

## 実行方法

```bash
# 1. アプリケーションイメージを作る
./gradlew bootBuildImage

# 2. dev 環境を起動する
docker compose -f docker-compose.dev.yaml up -d

# 3. シナリオテストを実行する (profile 指定時のみ runn サービスが有効になる)
docker compose -f docker-compose.dev.yaml --profile scenario run --rm runn
```

`runn` サービスは `scenario/` を `/books` に read-only でマウントし、`run --verbose /books/**/*.yml` を実行する。
オプションを変えたいときは compose の `command` を上書きする。

```bash
# 特定の runbook だけ、debug 出力付きで実行する
docker compose -f docker-compose.dev.yaml --profile scenario run --rm runn run --debug /books/oidc-login.yml
```

app には healthcheck を付けられない (native image に shell がない) ため、各 runbook の先頭 step で
`/actuator/health` が 200 を返すまで待つ。

### ホストから直接実行する場合

runbook は環境変数 `IDP_ISSUER` (既定 `http://localhost:18080`) を参照する。
ホストからはポート公開 (`18080:8080`) でそのまま到達できるため、追加設定なしで実行できる。

```bash
runn run scenario/*.yml
```

## runbook 一覧

| runbook | 内容 |
|---|---|
| `oidc-login.yml` | Discovery 取得 → `/api/login` でログイン (cookie 保持) → 認可エンドポイントへ遷移し `code` 付き 302 を確認 |

### `oidc-login.yml` の step

1. `wait_for_idp`: `/actuator/health` が 200 になるまで待つ
2. `discovery`: `/.well-known/openid-configuration` を取得し、`issuer` と endpoint を検証する。以降の step は Discovery の `authorization_endpoint` から解決した path を使う
3. `login`: 同一オリジンのログインページからの `fetch` として `POST /api/login` (`Origin` は issuer)。レスポンス body (spec.md §4.1) と `HttpOnly` なセッション cookie を検証する
4. `authorize`: セッション cookie 付きで `GET /oauth2/authorize` (`scope=openid tenant.read`、PKCE S256)。`redirect_uri` への 302 と `code` / `state` を検証し、`error` がないことを確認する

runn の HTTP runner は runner の endpoint 起点の path しか扱えないため、Discovery の絶対 URL は
`issuer` を prefix として検証したうえで path に変換している。

## スコープ外

- 未ログイン状態で認可エンドポイントに到達 → ログインページへ遷移 → `/api/login` → 認可フロー再開
- ログインページを別ドメインへ分離した構成 (CORS preflight と `Access-Control-*` の検証)
- `token_endpoint` での code 交換と ID Token (`nonce`, `auth_time`, `sid`) の検証
- Token Exchange (tenant_access → event_access)
