# Crowsi PA Key Agent

Policy Administrator用Ed25519鍵をplatform custody内で生成・保持し、公開情報だけを
owner-only JSONへ投影するローカルnative境界です。秘密鍵、seed、custody payloadを
標準出力、引数、環境変数、SQLite、公開状態ファイルへ出しません。
`initialize`は既存鍵を暗黙更新せず、custodyと公開状態が一致する場合だけ冪等です。
公開状態だけが残った場合は新しい鍵を生成せずfail closedにします。各コマンドは
有限の短命processとして終了し、Windowsユーザーに束縛されたcustody helperを
起動・解除・停止しません。
```bash
cargo run --locked --offline -- initialize \
  --state ${COELA_CONTROL_STATE_ROOT}/security/policy-authority/public-state.json \
  --custody ${COELA_CONTROL_STATE_ROOT}/security/platform-custody/runtime.json
```

`doctor`だけはロック・未接続をmetadata-only診断として返し、
それ以外はplatform custodyを利用できなければ処理を行いません。
Target device proof用の一回限り認可は、有限の専用portだけで発行します。

```bash
crowsi-pa-key-agent operation-authorize-once --config /absolute/owner-config.json \
  --config-sha256 sha256:<64lowerhex> \
  < operation-authorize-once-request.json > operation-only-request.json
```

`--config`はcanonical owner `0600`で、launcherが渡す小文字hexの完全な
`--config-sha256 sha256:<64lowerhex>`と一致し、固定root trust
`/etc/crowsi/policy-authority/operation-authorize-once-v2.json`にpinされた独立設定鍵で
署名します。設定はiHAT assertion/status/FreshUV/AuthorityResponseの別鍵、最小config
generation、FreshUV account binding、PA
state/custody/replayの絶対pathと、`(owner, service, device, proof-key-ref)`から
`custody_credential_id`、revision、Ed25519 classへの単一mappingだけを含みます。
proof-key-refとcustody credential IDは別fieldであり、同一視しません。
stdinは64 KiB以下のcurrent-only v2 requestです。selected identity、Begin、Finish、
submission-current identityの4つの署名済みiHAT exchangeを必須とし、裸のidentity/FreshUVと
v1を拒否します。PAはAuthorityResponse署名・世代順、Begin↔Finish、stable actor context、
prepared operation、`TargetApprove`、unsigned target-proof、trusted timeと全nonceを検証し、
root-signed mappingが選ぶcredentialに対する
`Sign(Ed25519, sha256(target-proof-binding))`だけを認可します。独立PA鍵で完全な
`OperationOnlyRequest`を署名した後、strict decodeした全requestのdomain-separated canonical
digest、raw target-proof digest、request ID digestとcanonical response bytesをowner `0700`
台帳へatomic fsync commitしてからstdoutへ返します。同一exact retryは、live evidence TTL、
現行mapping、PA public state、custodyへ再アクセスせず、期限後でもretention内は同じ署名済み
bytesを返します。同じproofやrequest IDへのfield substitutionは拒否します。初回accept後の
`Prepared`はissued time、PA public key/custody revision、mapping digestをpinするため、再起動後も
保持された旧revisionだけが完了でき、新しいPA鍵では代替できません。旧revisionが消失した
場合は外部応答前にfail closedとなるので、endpointはproof expiry後に元operationをCancel/resetし、
新しいPA request IDで再開してください。

launcherはfresh responseをhandler開始時刻ではなくPA subprocessの完了時刻で検証します。
stdout消失後のretryはendpoint側の同一operation journalとPAのexact cacheを用い、別requestへ
読み替えません。ledgerはexclusive OS lock、owner `0600` fd-relative files、atomic temp
fsync/rename/directory fsync、bounded quota、期限切れretention、durable time high-watermarkを使います。
clock rollbackはfail closedです。秘密、汎用get/put/delete、caller選択provider actionは
出力・公開しません。
旧v1 consumed-proof fileはone-use tombstoneとしてのみ厳密に移行し、responseを再生成しません。

```bash
crowsi-pa-key-agent doctor --state /absolute/public-state.json --custody /absolute/custody.json
crowsi-pa-key-agent initialize --state /absolute/public-state.json --custody /absolute/custody.json
crowsi-pa-key-agent status --state /absolute/public-state.json --custody /absolute/custody.json
```

信頼領域の破棄には、owner-onlyな閉じたintent、現在のPA世代へ登録されたPasskey、
短命challengeを必須とします。UIや上位Coordinatorは次の順序で呼び出します。

```bash
crowsi-pa-key-agent trust-domain-destroy-preflight \
  --state /absolute/public-state.json --credential /absolute/passkey.json \
  --intent /absolute/destruction-intent.json --custody /absolute/custody.json
crowsi-pa-key-agent trust-domain-destroy-challenge \
  --state /absolute/public-state.json --credential /absolute/passkey.json \
  --intent /absolute/destruction-intent.json --challenge /absolute/challenge.json \
  --custody /absolute/custody.json
crowsi-pa-key-agent trust-domain-destroy-finish \
  --state /absolute/public-state.json --credential /absolute/passkey.json \
  --intent /absolute/destruction-intent.json --challenge /absolute/challenge.json \
  --assertion /absolute/assertion.json --custody /absolute/custody.json
```

intentは`operation_id`、`local-trust-domain` scope、現在のPA公開鍵、影響範囲digestを
正規化してchallengeへ結合します。finishはUP/UV、P-256署名、counter、RP/Origin、
PA世代とintent digestを再検証した後だけ、Passkey登録、PA鍵、公開状態の順で削除します。
別の資格情報、Authenticator側の秘密鍵、共有daemonには触れません。
`destroy-native`は復旧試験用の低レベル操作です。Passkey認可を行わないため、通常の
UI、サービス、運用手順から直接呼び出してはいけません。
認証器を紛失して既存Passkeyで再照合できない場合は、現行PAと外部資格情報を
保持したままサーバー側登録だけを失効できます。この操作は現在のplatform custody
revisionと公開鍵、正規のowner-only path、固定確認文をすべて再検証します。
```bash
crowsi-pa-key-agent passkey-recovery-revoke \
  --state /absolute/policy-authority/public-state.json \
  --credential /absolute/policy-authority/passkey.json \
  --confirm-public-key CURRENT_PA_PUBLIC_KEY \
  --confirmation revoke-lost-passkey-registration \
  --custody /absolute/custody.json
```

対象は同じディレクトリの`public-state.json`と`passkey.json`へ固定されます。
PA鍵・公開状態・runtime・外部資格情報・認証器内Credentialは変更しません。
認証器内の表示はOS側で別途削除します。サーバー登録失効後の再登録は通常buildと
federated artifactではfail closedです。後述するowner-local artifactでは、owner OS
sessionをTCBとする明示的な単一ユーザー配備に限り、新しい登録を開始できます。
出力される`public_key_hex`はCredential Agentがpinする64文字のEd25519公開鍵です。
公開状態の汎用認可発行は`blocked`のままです。許可対象は、Credential enrollmentと
読取専用GitHub observerの2つのpurpose-specific Coordinatorに限定します。後者は
`observe-provider`、`crowsi://credentials/github-app/<credential-ref>`、
`github-app-jwt-signing`の完全一致だけを受け付けます。どちらもowner-onlyなPasskey登録と
短命challengeを使い、RP ID、Origin、P-256署名、UP/UV、counter、期限、PA世代と正確な
request digestを検証してから30秒有効のEnvelopeを新規0600ファイルへ発行します。
challengeとassertionは検証時に消費され、Envelopeの再利用はLocal Control Bridgeの
SQLite fenceが拒否します。
Credential enrollmentをDevice Flowの完了後に確定する場合、challengeには実際に
WebAuthnを呼び出すlocalhost originを明示します。RP IDは`localhost`のままですが、
portを含むoriginはchallenge・clientData・assertion検証で完全一致します。

```bash
crowsi-pa-key-agent credential-authorization-challenge \
  --state /absolute/policy-authority/public-state.json \
  --credential /absolute/policy-authority/passkey.json \
  --request /absolute/credential-request.json \
  --challenge /absolute/credential-challenge.json \
  --custody /absolute/platform-custody/runtime.json \
  --identity-assertion /absolute/identity/device-identity-assertion.json \
  --identity-status /absolute/identity/current-device-status.json \
  --identity-trust /absolute/identity/policy-authority-trust.json \
  --origin http://localhost:4213
```
認可Challengeと発行には、iHAT Identity Authorityが署名した短命の
`ihat://identity/device-identity-assertion/v1`、30秒以内の署名済み
`ihat://identity/current-device-status/v1`、配備時にpinしたidentity trust v2を
`--identity-assertion`、`--identity-status`、`--identity-trust`で必須指定します。PAはissuer、
audience、`service:crowsi`、両署名、期限と全bindingを再検証し、pairwise subject、端末ID、
non-exportable proof-key参照、posture revision、subject/service/device/sessionの各
失効epochをAuthorization V2へ写します。Current status nonceはPA stateと同じowner-only
領域の永続台帳でchallenge発行時に一回だけ消費し、同時実行と再起動後のreplayを拒否します。
Passkey credential IDから端末IDを推定したり、
固定subject・固定posture・固定epochへfallbackしたりしません。
登録直後の所有確認だけはWindows authenticatorの初期counter同値を許容しますが、
counterの減少と登録後の認証での非増加は引き続き拒否します。
登録確認の拒否理由は、Base64url encoding、最小長、UP、UV、backup flags、
RP ID、Origin、credential binding、署名、counterの固定語彙へ分離します。
`PasskeyRegistrationDiagnosticEventV1`は任意のTelemetry envelopeへ渡せる
非秘密属性だけを生成します。Authenticator data、credential ID、challenge、署名、
Origin、利用者情報は型に含まず、通常認証の診断oracleとしても使用しません。
新規Passkey登録は通常buildでfail closedです。`passkey-register-challenge` / `stage` /
`confirm`はcustodyやpathを読む前に
`pa-passkey-bootstrap-authorizer-not-provisioned`で終了し、登録内部APIもdefault
artifactにはexportされません。`bootstrap-authorizer-internal` featureは登録検証testと
将来のprivileged authorizer向けです。
ローカル単一ユーザー配備だけは`owner-local-bootstrap` featureを明示してbuildできます。
このfeatureは`bootstrap-authorizer-internal`を含み、CLIの完全な引数を保持したまま、
各段階でplatform custodyと現在のPA revisionを再検証し、内部算出したPA bindingを登録検証へ
渡します。WebAuthnのAT data・credential ID・CTAP2 canonical COSE ES256/RS256鍵を照合し、別challengeへの
UV署名が成功するまでcommitしません。Chromiumがresident credential向けに付与する
`credProtect`等のauthenticator extensionは、COSE鍵との境界、CBOR map、重複、末尾を
検証してから受理します。これはowner OS sessionをTCBとする配備方針であり、
Cargo feature自体を認可やsame-UID隔離とはみなしません。

```bash
cargo build --locked --offline --features owner-local-bootstrap
```

same-UIDを非信頼とする配備ではこのfeatureを使用せず、Passkey登録とceremony stateを
rootまたは専用UIDのbrokerへ移したうえでpolkit等のbootstrap authorizerを使用します。
登録内部処理は`localhost`の同一originに限定し、AT flag付きauthenticator dataの
credential IDとCOSE ES256/RS256鍵をbrowser申告値と照合します。さらに別の一回利用challengeへの
UV付き`webauthn.get`署名で鍵所持を証明した後だけcommitします。有効またはstaleな
既存登録は新規登録で上書きせず、`passkey-rebind-*`で既存認証器のUV署名を
検証した場合だけ現行PAへ再結合します。
PAを完全破棄しても、認証器側のPasskey秘密鍵はOSの管理下に残ります。サーバー側
登録は失効しますが、認証器の表示も消す場合はWindows等のPasskey管理画面で
ユーザーが削除します。custody利用可否だけを本人確認とするfallbackはありません。

登録後の所有者再認証は、上位UIが短命challengeを作成し、同じlocalhost originで得た
WebAuthn assertionを検証する二段階契約です。成功時には秘密を含まないreceiptだけを返します。
challenge、assertion、credential counter、PA generationを完全一致で検証し、成功したchallengeは
一回で消費します。拒否時は上位がceremony directoryごと破棄します。ブラウザsessionの発行と寿命は上位アプリの責務で、
Crowsiはcookieやアプリsessionを保持しません。

```bash
crowsi-pa-key-agent passkey-authentication-challenge \
  --state /absolute/policy-authority/public-state.json \
  --credential /absolute/policy-authority/passkey.json \
  --challenge /absolute/authentication-challenge.json \
  --custody /absolute/platform-custody/runtime.json
crowsi-pa-key-agent passkey-authenticate \
  --state /absolute/policy-authority/public-state.json \
  --credential /absolute/policy-authority/passkey.json \
  --challenge /absolute/authentication-challenge.json \
  --assertion /absolute/authentication-assertion.json \
  --custody /absolute/platform-custody/runtime.json
```

通常artifactの閉域と、予約された登録内部処理を別々に検証します。

```bash
# WONDERLAND_ROOT is the workspace checkout root.
"$WONDERLAND_ROOT/bin/verify-repositories" --rust --tier standard
```
