export const DEFAULT_COUNTRY_CODE = "NG";

/** Nigerian states and the Federal Capital Territory (36 + FCT). */
export const NIGERIA_STATES: readonly string[] = [
  "Abia",
  "Abuja Federal Capital Territory",
  "Adamawa",
  "Akwa Ibom",
  "Anambra",
  "Bauchi",
  "Bayelsa",
  "Benue",
  "Borno",
  "Cross River",
  "Delta",
  "Ebonyi",
  "Edo",
  "Ekiti",
  "Enugu",
  "Gombe",
  "Imo",
  "Jigawa",
  "Kaduna",
  "Kano",
  "Katsina",
  "Kebbi",
  "Kogi",
  "Kwara",
  "Lagos",
  "Nasarawa",
  "Niger",
  "Ogun",
  "Ondo",
  "Osun",
  "Oyo",
  "Plateau",
  "Rivers",
  "Sokoto",
  "Taraba",
  "Yobe",
  "Zamfara",
] as const;

/** Legacy/alternate labels accepted for Nigerian states. */
const NIGERIA_STATE_ALIASES: Record<string, string> = {
  "federal capital territory": "Abuja Federal Capital Territory",
  fct: "Abuja Federal Capital Territory",
  abuja: "Abuja Federal Capital Territory",
};

function canonicalNigeriaState(state: string): string | null {
  const trimmed = state.trim();
  if (!trimmed) return null;
  const lower = trimmed.toLowerCase();
  const alias = NIGERIA_STATE_ALIASES[lower];
  if (alias) return alias;
  const found = NIGERIA_STATES.find((s) => s.toLowerCase() === lower);
  return found ?? null;
}

export function normalizeCountryCode(code: string): string {
  return code.trim().toUpperCase();
}

export function isValidCountryCode(code: string): boolean {
  return /^[A-Z]{2}$/.test(normalizeCountryCode(code));
}

export function isValidNigeriaState(state: string): boolean {
  return canonicalNigeriaState(state) !== null;
}

export interface ContactDetailsInput {
  fullName: string;
  address: string;
  phone: string;
  country?: string;
  state?: string;
}

export function normalizeContactDetails(
  details: ContactDetailsInput,
  label: string
): { fullName: string; address: string; phone: string; country: string; state: string } {
  const fullName = details.fullName?.trim() ?? "";
  const address = details.address?.trim() ?? "";
  const phone = details.phone?.trim() ?? "";
  const country = normalizeCountryCode(details.country?.trim() || DEFAULT_COUNTRY_CODE);
  const state = details.state?.trim() ?? "";

  if (!fullName) throw new Error(`${label} full name is required`);
  if (!address) throw new Error(`${label} address is required`);
  if (!phone) throw new Error(`${label} phone is required`);
  if (!isValidCountryCode(country)) {
    throw new Error(`${label} country must be a valid ISO 3166-1 alpha-2 code`);
  }

  let canonicalState: string;
  if (country === DEFAULT_COUNTRY_CODE) {
    const nigeriaState = canonicalNigeriaState(state);
    if (!nigeriaState) {
      throw new Error(`${label} state is required and must be a valid Nigerian state`);
    }
    canonicalState = nigeriaState;
  } else {
    if (!state) {
      throw new Error(`${label} state or region is required`);
    }
    canonicalState = state;
  }

  return { fullName, address, phone, country, state: canonicalState };
}
