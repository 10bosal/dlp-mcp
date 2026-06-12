# DLP MCP

ChatGPT에 업로드된 **암호화 파일을 복호화**하여 추론에 사용할 수 있게 해주는 MCP(Model Context Protocol) 서버입니다.

DLP(Data Loss Prevention) 맥락에서 암호화된 민감 파일을 안전하게 복호화·전달하는 게이트웨이 역할을 합니다.

## 아키텍처

```
[사용자] → 암호화 파일 업로드 → [ChatGPT]
                                    ↓
                            MCP tool: decrypt_file
                                    ↓
                            [DLP MCP @ fly.io]
                                    ↓
                     임시 폴더 저장 + content_b64 반환
                                    ↓
                            [ChatGPT 추론]
```

## 암호화 포맷

- **알고리즘**: AES-GCM (키 길이: 128/192/256-bit)
- **기본 파일 포맷**: `[12-byte nonce][ciphertext + 16-byte auth tag]`
- 외부 nonce 사용 시 `nonce_b64` 파라미터로 전달

## MCP Tools

### `decrypt_file`

| 파라미터 | 설명 |
|----------|------|
| `encrypted_data_b64` | Base64 인코딩된 암호화 파일 |
| `filename` | 원본 파일명 (기본: `decrypted.bin`) |
| `mime_type` | MIME 타입 힌트 (선택) |
| `nonce_b64` | 외부 nonce (선택) |
| `associated_data_b64` | AES-GCM AAD (선택) |

반환값에 `content_b64`(복호화 본문), `content_text`(텍스트인 경우), `temp_path`(서버 임시 경로) 포함.

### `cleanup_temp_files`

TTL이 지난 임시 복호화 파일을 삭제합니다.

## 로컬 실행

```bash
cd work/dlp-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 키 생성
export DECRYPTION_KEY_HEX=$(openssl rand -hex 32)
export MCP_API_KEY=your-secret-token   # 선택

dlp-mcp
# 또는: uvicorn dlp_mcp.server:app --host 0.0.0.0 --port 8000
```

헬스체크: `curl http://localhost:8000/health`

## 문서 암호화

문서 암호화는 별도 프로젝트 [dlp-encrypt](../dlp-encrypt)를 사용합니다.

```bash
cd ../dlp-encrypt
pip install -e .

export ENCRYPTION_KEY_HEX=$DECRYPTION_KEY_HEX
dlp-encrypt sample.txt --print-b64
```

## fly.io 배포

```bash
fly launch --no-deploy          # fly.toml 확인 후
fly secrets set DECRYPTION_KEY_HEX=<64자 hex>
fly secrets set MCP_API_KEY=<랜덤 토큰>
fly deploy
```

배포 URL 예: `https://dlp-mcp.fly.dev`

ChatGPT MCP 연동 시 Streamable HTTP 엔드포인트(`/mcp`)와 Bearer 인증(`MCP_API_KEY`)을 설정합니다.

## 환경 변수

| 변수 | 필수 | 설명 |
|------|------|------|
| `DECRYPTION_KEY_HEX` | ✅ | AES 키 (hex) |
| `MCP_API_KEY` | | HTTP Bearer 인증 토큰 |
| `TEMP_DIR` | | 임시 저장 경로 (기본: `/tmp/dlp-mcp`) |
| `MAX_FILE_SIZE_MB` | | 최대 파일 크기 (기본: 50) |
| `TEMP_TTL_SECONDS` | | 임시 파일 TTL (기본: 3600) |

## GitHub 등록

```bash
cd work/dlp-mcp
git init
git add .
git commit -m "Initial commit: DLP MCP decrypt server"
gh repo create dlp-mcp --private --source=. --push
```

## 보안 참고

- 복호화 키는 fly.io secrets에만 저장하고 코드/이미지에 포함하지 마세요.
- `MCP_API_KEY`로 무단 호출을 차단하세요.
- 임시 파일은 TTL 후 `cleanup_temp_files`로 정리하거나 fly.io ephemeral storage 특성을 활용하세요.
- 민감 데이터는 복호화 후 최소한의 시간만 서버에 보관하세요.
