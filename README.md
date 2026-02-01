# Raw TCP Handshake in Go

Go言語のRaw Socket (`syscall.SOCK_RAW`) を使用して、TCPの3ウェイハンドシェイク（SYN -> SYN-ACK -> ACK）を手動で実装した学習用プロジェクトです。
OSのTCPスタックを介さず、IPヘッダーとTCPヘッダーを自力で構築・バイナリ化して送信します。

## ⚠️ 注意事項

- **Root権限が必要です**: Raw Socketを使用するため、実行には `sudo` が必要です。
- **Linux専用です**: `syscall` パッケージのLinux固有の定数を使用しています。
- **カーネルの挙動**: 手動でパケットを送信するため、Linuxカーネル自体は「このTCP接続を知らない」状態になります。そのため、サーバーからSYN-ACKが返ってきた際に、カーネルが勝手にRST（Reset）パケットを送り返してしまうことがあります。
  - これを防ぐには、一時的に `iptables` などでRSTパケットの送出を抑制する必要がある場合があります。

## 実行方法

複数のファイルを指定して実行します。引数として送信先のIPアドレスとポート番号を指定してください。

```bash
# 書式
sudo go run main.go headers.go checksum.go <送信先IP> <送信先ポート>
```

### 実行例

```bash
# example.com (93.184.216.34) のポート80に接続する場合
sudo go run main.go headers.go checksum.go 93.184.216.34 80
```

## 動作の流れ

1. **SYN送信**: ランダムなシーケンス番号でSYNパケットを作成し送信します。
2. **SYN-ACK受信**: サーバーからの応答をRaw Socketで監視・受信します。
3. **ACK送信**: 受信したSYN-ACKの確認応答番号などを元に、ACKパケットを作成して送信し、ハンドシェイクを完了させます。

## ファイル構成

- `main.go`: プログラムのメインロジック。パケットの送受信フローを制御します。
- `headers.go`: IPv4ヘッダーおよびTCPヘッダーの構造体定義と、バイト列への変換処理（Marshaler）。
- `checksum.go`: チェックサムの計算ロジック。
- `test_packet.go`: パケット構築とパース処理の単体テスト用プログラム。
- `go.mod`: Goモジュール定義ファイル。
