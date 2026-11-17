# CyberAgent SaaS — Cloudflare Workers + D1 + Workers AI + Razorpay

This is a starter implementation, not a legally/commercially audited payment product.
Review, test, and configure it before accepting real payments.

## Product behavior
- Owner: first account registered with `OWNER_SETUP_TOKEN` becomes admin; admin chat does not deduct credits.
- Normal signup: 10 free messages.
- ₹49 one-time pack: 50 message credits (configurable with `PAID_CREDITS`).
- Payment: Razorpay Orders API + server-side signature check + captured-payment status check + `order.paid` webhook.
- AI: Cloudflare Workers AI binding; default `@cf/google/gemma-4-26b-a4b-it`.
- Database: Cloudflare D1.
- Admin: revenue/orders/users, disable/enable accounts, grant 10 credits.
- Passwords: PBKDF2 hashes; session cookie is HttpOnly, Secure, SameSite=Lax.

## Free-tier reality
This does not provide unlimited AI. Workers AI free allocation is currently limited to 10,000 Neurons/day, and Cloudflare free plans have request/CPU/database limits. Razorpay processing fees and any taxes/settlement terms may apply. ₹49 revenue is not profit. Do not advertise unlimited messages.
The 16 models on the Android/Termux device are not deployed by this package. This package uses Cloudflare Workers AI.

## 1. Requirements
- Cloudflare account
- Razorpay account with website/business onboarding completed, API keys and payment activation
- Termux with Node.js LTS and npm/npx
- A domain is optional; `workers.dev` URL can be used

## 2. Install and extract
Copy the ZIP into Android Downloads, then in Termux:
```bash
pkg update -y
pkg install -y nodejs-lts unzip
termux-setup-storage
mkdir -p ~/CyberAgentSaaS
unzip ~/storage/downloads/cyberagent-saas.zip -d ~/CyberAgentSaaS
cd ~/CyberAgentSaaS/cyberagent-saas
```

## 3. Create D1 database
```bash
npx wrangler login
npx wrangler d1 create cyberagent-saas-db
```
Copy the returned database UUID. Edit `wrangler.jsonc` and replace `REPLACE_WITH_D1_DATABASE_ID` with that UUID. Do not put API secrets in this file.

Apply schema:
```bash
npx wrangler d1 migrations apply cyberagent-saas-db --remote
```

## 4. Configure secrets
Razorpay Dashboard: create API keys in Test Mode first.
```bash
npx wrangler secret put RAZORPAY_KEY_ID
npx wrangler secret put RAZORPAY_KEY_SECRET
npx wrangler secret put RAZORPAY_WEBHOOK_SECRET
npx wrangler secret put OWNER_SETUP_TOKEN
```
Enter each value when prompted. `OWNER_SETUP_TOKEN` should be a long random secret known only to you.

In Razorpay Dashboard, configure webhook URL:
`https://YOUR-WORKER.workers.dev/api/razorpay-webhook`
Subscribe to `order.paid`. Use the same webhook secret as `RAZORPAY_WEBHOOK_SECRET`.

## 5. Deploy
```bash
npx wrangler deploy
```
Open the workers.dev URL.

## 6. Create owner account (IMPORTANT)
On the website create your account first. Enter the exact `OWNER_SETUP_TOKEN` in the "Owner setup code" field. This token makes the first eligible signup an admin. Only do this yourself. Once your owner account is created, immediately remove the setup secret:
```bash
npx wrangler secret delete OWNER_SETUP_TOKEN
```
If a non-owner registers first without the token, they remain a normal user. Do not share the setup token.

## 7. Test payments
- Keep Razorpay in Test Mode.
- Test signup: normal users should get 10 free messages.
- Test admin: owner should get no credit deductions.
- Test ₹49 checkout with Razorpay test credentials and test payment method.
- Check admin dashboard; paid order should add 50 credits.
- Only after end-to-end test, use live Razorpay keys if your account is approved.
- Ensure Razorpay auto-capture is enabled. This integration verifies payment status is `captured`.

## 8. Change paid credits
In `wrangler.jsonc`, edit `"PAID_CREDITS": "50"` and redeploy. This is a one-time credit pack, not an auto-renewing subscription.

## 9. Important limitations and security review
- No email verification or password reset flow is included. Before a public launch, add verified email/password recovery and privacy/terms/refund/support pages.
- No production-grade bot protection, distributed rate-limit service, or accounting reconciliation dashboard. Add these before significant traffic.
- Admin setup token must be deleted immediately after owner registration.
- Never expose Razorpay key secret or webhook secret in browser code.
- Payment verification uses signature plus a server-side payment status fetch; webhook is also signature-verified and idempotent by payment ID.
- AI message credits are decremented before inference and refunded on AI failure; owner is exempt.
- Basic defensive AI only. It refuses credential theft, account intrusion, malware, and unauthorized hacking.
- Never collect users' Instagram passwords, OTPs, session cookies, or API keys.
- This code is a starter. Get a security review and check Razorpay/Cloudflare current terms before taking real money.

## Official docs
- Razorpay standard checkout / signature verification: https://razorpay.com/docs/payments/payment-gateway/web-integration/standard/
- Razorpay webhooks: https://razorpay.com/docs/webhooks/
- Cloudflare D1: https://developers.cloudflare.com/d1/
- Workers AI pricing: https://developers.cloudflare.com/workers-ai/platform/pricing/
