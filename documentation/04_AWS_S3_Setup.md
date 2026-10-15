# 04: AWS S3 Setup Guide

> **Cost note:** New AWS accounts created after 15 July 2025 can pick the **Free plan**, which gives $100 in credits at sign-up (up to $200 by completing activities). The plan ends after 6 months or when credits run out, and there are no charges unless you upgrade. A demo with a few hundred MB in S3 costs a negligible fraction of those credits. **Do not use AWS KMS** (it has a monthly per-key cost); this design doesn't need it.

## 1. Account setup
1. Sign up at aws.amazon.com and choose the **Free plan**.
2. Enable **MFA** on the root user, then stop using root.
3. **Billing → Budgets → Create budget:** monthly cost budget of $5, with an email alert at 50%.
4. Select region **Asia Pacific (Mumbai) `ap-south-1`**.

## 2. Create the bucket
Console → S3 → Create bucket:

| Setting | Value |
|---|---|
| Name | `securevault-<yourname>-<random4>` (globally unique, lowercase) |
| Region | `ap-south-1` |
| Object Ownership | ACLs disabled (bucket owner enforced) |
| Block Public Access | **All four ON** |
| Bucket Versioning | **Disabled** (see revocation, doc 03 §7) |
| Default encryption | SSE-S3 (free; defense in depth only) |

### Lifecycle rule (housekeeping)
Add a rule that aborts incomplete multipart uploads after 1 day.

### CORS
Not required. The client is a Python app, not a browser. Add CORS only if you later build a web client.

## 3. IAM user for the backend (least privilege)
IAM → Users → Create user `securevault-backend` (no console access) → attach an inline policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ObjectRW",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::securevault-<yourname>-<random4>/objects/*"
    },
    {
      "Sid": "ListPrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::securevault-<yourname>-<random4>",
      "Condition": { "StringLike": { "s3:prefix": ["objects/*"] } }
    }
  ]
}
```

Create an **access key** (use case: "Application running outside AWS"). Put it in the backend `.env` only. **Never commit it.**

Optional bucket policy that refuses non-TLS access:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": [
      "arn:aws:s3:::securevault-<yourname>-<random4>",
      "arn:aws:s3:::securevault-<yourname>-<random4>/*"
    ],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }]
}
```

## 4. Backend configuration (`backend/.env`)
```env
DATABASE_URL=postgresql+psycopg2://sv:sv@db:5432/securevault
JWT_SECRET=<64 random hex chars>
JWT_TTL_MINUTES=30
KA_PASSPHRASE=<long passphrase for msk.enc>
STORAGE_BACKEND=s3                # s3 | moto
AWS_REGION=ap-south-1
S3_BUCKET=securevault-<yourname>-<random4>
S3_PREFIX=objects/
AWS_ACCESS_KEY_ID=<from IAM>
AWS_SECRET_ACCESS_KEY=<from IAM>
PRESIGN_TTL_SECONDS=300
```
Add `.env` to `.gitignore` and commit a `.env.example` with placeholder values.

## 5. Storage module contract (`backend/app/storage.py`)
```python
class Storage(Protocol):
    def presign_put(self, object_key: str, size: int) -> str: ...
    def presign_get(self, object_key: str) -> str: ...
    def head(self, object_key: str) -> int | None: ...   # returns size or None
    def delete(self, object_key: str) -> None: ...
```

S3 implementation notes:
- `boto3.client("s3", region_name=AWS_REGION, config=Config(signature_version="s3v4"))`
- `generate_presigned_url("put_object", Params={"Bucket": B, "Key": k, "ContentType": "application/octet-stream"}, ExpiresIn=300)`
  - The client **must** send the same `Content-Type` header on PUT, or the signature fails.
- Object keys follow `objects/<file_uuid>/<version>.svlt`. Never use the original filename.
- After the client PUTs, `/files/{id}/complete` calls `head()` and rejects the file if the size doesn't match.

## 6. Verify the setup
```bash
aws configure --profile securevault        # uses the IAM key
aws s3 cp test.txt s3://<bucket>/objects/test.txt --profile securevault   # should work
aws s3 ls s3://<bucket>/ --profile securevault                           # only objects/ prefix allowed
aws s3 cp s3://<bucket>/objects/test.txt - --profile securevault
aws s3 rm s3://<bucket>/objects/test.txt --profile securevault
```

## 7. Before the plan expires
- Export the demo bucket contents if needed: `aws s3 sync`.
- Delete the bucket and IAM user after evaluation, or upgrade to Paid knowingly.
- Tests use **moto**, so development never depends on the live account.
