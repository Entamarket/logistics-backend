import { DEFAULT_COUNTRY_CODE } from "./nigeria-locations";

export const BASE_FEE_NGN = 1500;
export const RATE_PER_KM_NGN = 120;

export const VOLUME_SMALL_MAX_CM3 = 20_000;
export const VOLUME_MEDIUM_MAX_CM3 = 80_000;
export const VOLUME_LARGE_MAX_CM3 = 200_000;

export type DimensionCategory = "small" | "medium" | "large" | "extraLarge";

export interface ShipmentPriceBreakdown {
  currency: "NGN";
  baseFee: number;
  distanceMeters: number;
  distanceKm: number;
  distanceFee: number;
  weightFee: number;
  volumeCm3: number;
  dimensionCategory: DimensionCategory;
  dimensionFee: number;
  total: number;
}

export interface ContactAddressInput {
  address: string;
  state?: string;
  country?: string;
}

const COUNTRY_LABELS: Record<string, string> = {
  NG: "Nigeria",
};

export function countryLabel(code: string | undefined): string {
  if (!code) return COUNTRY_LABELS[DEFAULT_COUNTRY_CODE] ?? "Nigeria";
  return COUNTRY_LABELS[code.toUpperCase()] ?? code;
}

export function formatContactAddress(contact: ContactAddressInput): string {
  const address = contact.address?.trim() ?? "";
  const state = contact.state?.trim() ?? "";
  const countryName = countryLabel(contact.country?.trim() || DEFAULT_COUNTRY_CODE);
  const parts = [address, state, countryName].filter(Boolean);
  return parts.join(", ");
}

export function roundedKmFromMeters(distanceMeters: number): number {
  if (!Number.isFinite(distanceMeters) || distanceMeters < 0) return 0;
  return Math.round(distanceMeters / 1000);
}

export function distanceFeeNgn(distanceMeters: number): number {
  const km = roundedKmFromMeters(distanceMeters);
  if (km < 1) return 0;
  return km * RATE_PER_KM_NGN;
}

/** Weight tiers: ≤5 kg free; (5,10] ₦500; (10,20] ₦1000; >20 ₦1500 */
export function weightFeeNgn(weightKg: number): number {
  if (!Number.isFinite(weightKg) || weightKg < 0) return 0;
  if (weightKg <= 5) return 0;
  if (weightKg <= 10) return 500;
  if (weightKg <= 20) return 1000;
  return 1500;
}

export function volumeCm3(lengthCm: number, widthCm: number, heightCm: number): number {
  if (!Number.isFinite(lengthCm) || !Number.isFinite(widthCm) || !Number.isFinite(heightCm)) return 0;
  if (lengthCm < 0 || widthCm < 0 || heightCm < 0) return 0;
  return lengthCm * widthCm * heightCm;
}

/** Volume tiers: ≤20k small; (20k,80k] medium; (80k,200k] large; >200k extraLarge */
export function dimensionCategoryFromVolume(vol: number): DimensionCategory {
  if (!Number.isFinite(vol) || vol <= VOLUME_SMALL_MAX_CM3) return "small";
  if (vol <= VOLUME_MEDIUM_MAX_CM3) return "medium";
  if (vol <= VOLUME_LARGE_MAX_CM3) return "large";
  return "extraLarge";
}

export function dimensionFeeNgn(vol: number): number {
  const category = dimensionCategoryFromVolume(vol);
  if (category === "small") return 0;
  if (category === "medium") return 500;
  if (category === "large") return 1000;
  return 1500;
}

export function parsePackageDimensions(
  lengthCm: unknown,
  widthCm: unknown,
  heightCm: unknown
): { lengthCm: number; widthCm: number; heightCm: number } {
  const l = Number(lengthCm);
  const w = Number(widthCm);
  const h = Number(heightCm);
  if (!Number.isFinite(l) || !Number.isFinite(w) || !Number.isFinite(h) || l < 0 || w < 0 || h < 0) {
    throw new Error("lengthCm, widthCm, and heightCm must be non-negative numbers");
  }
  return { lengthCm: l, widthCm: w, heightCm: h };
}

export function computeShipmentPrice(
  distanceMeters: number,
  weightKg: number,
  lengthCm: number,
  widthCm: number,
  heightCm: number
): ShipmentPriceBreakdown {
  const distanceKm = roundedKmFromMeters(distanceMeters);
  const baseFee = BASE_FEE_NGN;
  const distanceFee = distanceFeeNgn(distanceMeters);
  const weightFee = weightFeeNgn(weightKg);
  const vol = volumeCm3(lengthCm, widthCm, heightCm);
  const dimensionCategory = dimensionCategoryFromVolume(vol);
  const dimensionFee = dimensionFeeNgn(vol);
  return {
    currency: "NGN",
    baseFee,
    distanceMeters: Math.max(0, Math.round(distanceMeters)),
    distanceKm,
    distanceFee,
    weightFee,
    volumeCm3: vol,
    dimensionCategory,
    dimensionFee,
    total: baseFee + distanceFee + weightFee + dimensionFee,
  };
}
