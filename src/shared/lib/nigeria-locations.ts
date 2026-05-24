export const DEFAULT_COUNTRY_CODE = "NG";

/** Nigerian states and the Federal Capital Territory (36 + FCT). */
export const NIGERIA_STATES: readonly string[] = [
  "Abia",
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
  "Federal Capital Territory",
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

const NIGERIA_STATE_SET = new Set<string>(NIGERIA_STATES.map((s) => s.toLowerCase()));

export function normalizeCountryCode(code: string): string {
  return code.trim().toUpperCase();
}

export function isValidNigeriaState(state: string): boolean {
  const trimmed = state.trim();
  return trimmed.length > 0 && NIGERIA_STATE_SET.has(trimmed.toLowerCase());
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
  if (country !== DEFAULT_COUNTRY_CODE) {
    throw new Error(`${label} country must be Nigeria (NG)`);
  }
  if (!isValidNigeriaState(state)) {
    throw new Error(`${label} state is required and must be a valid Nigerian state`);
  }

  const canonicalState =
    NIGERIA_STATES.find((s) => s.toLowerCase() === state.toLowerCase()) ?? state;

  return { fullName, address, phone, country, state: canonicalState };
}
