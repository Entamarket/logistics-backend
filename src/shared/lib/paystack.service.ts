import crypto from "crypto";

const PAYSTACK_BASE = "https://api.paystack.co";

export interface PaystackInitializeResult {
  reference: string;
  accessCode: string;
  authorizationUrl: string;
}

export interface PaystackVerifyResult {
  status: string;
  reference: string;
  amountKobo: number;
  metadata: Record<string, unknown>;
}

function getSecretKey(): string {
  const key = process.env.PAYSTACK_SECRET_KEY?.trim();
  if (!key) {
    throw new Error("PAYSTACK_SECRET_KEY is not configured on the server.");
  }
  return key;
}

export function getPaystackPublicKey(): string {
  const key = process.env.PAYSTACK_PUBLIC_KEY?.trim();
  if (!key) {
    throw new Error("PAYSTACK_PUBLIC_KEY is not configured on the server.");
  }
  return key;
}

export function generatePaymentReference(shipmentId: string): string {
  const suffix = crypto.randomBytes(8).toString("hex");
  return `shp_${shipmentId}_${suffix}`;
}

export async function initializeTransaction(params: {
  email: string;
  amountKobo: number;
  reference: string;
  metadata: Record<string, string>;
}): Promise<PaystackInitializeResult> {
  const secret = getSecretKey();
  const res = await fetch(`${PAYSTACK_BASE}/transaction/initialize`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${secret}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      email: params.email,
      amount: params.amountKobo,
      reference: params.reference,
      metadata: params.metadata,
      currency: "NGN",
    }),
  });

  const json = (await res.json()) as {
    status?: boolean;
    message?: string;
    data?: {
      reference: string;
      access_code: string;
      authorization_url: string;
    };
  };

  if (!res.ok || !json.status || !json.data) {
    const msg = json.message || "Failed to initialize Paystack payment.";
    if (/duplicate transaction reference/i.test(msg)) {
      throw new Error(
        "A previous payment attempt is still open. Please try again; a new payment session will be started."
      );
    }
    throw new Error(msg);
  }

  return {
    reference: json.data.reference,
    accessCode: json.data.access_code,
    authorizationUrl: json.data.authorization_url,
  };
}

export async function verifyTransaction(reference: string): Promise<PaystackVerifyResult> {
  const secret = getSecretKey();
  const res = await fetch(`${PAYSTACK_BASE}/transaction/verify/${encodeURIComponent(reference)}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${secret}` },
  });

  const json = (await res.json()) as {
    status?: boolean;
    message?: string;
    data?: {
      status: string;
      reference: string;
      amount: number;
      metadata?: Record<string, unknown>;
    };
  };

  if (!res.ok || !json.status || !json.data) {
    throw new Error(json.message || "Failed to verify Paystack payment.");
  }

  return {
    status: json.data.status,
    reference: json.data.reference,
    amountKobo: json.data.amount,
    metadata: json.data.metadata ?? {},
  };
}

export function verifyWebhookSignature(rawBody: Buffer | string, signatureHeader: string | undefined): boolean {
  if (!signatureHeader) return false;
  const secret = getSecretKey();
  const hash = crypto.createHmac("sha512", secret).update(rawBody).digest("hex");
  const sigBuf = Buffer.from(signatureHeader);
  const hashBuf = Buffer.from(hash);
  if (sigBuf.length !== hashBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(hashBuf, sigBuf);
}
