/**
 * Server-side Google Maps (Geocoding + Distance Matrix).
 * Set GOOGLE_MAPS_API_KEY in backend .env; enable Geocoding API and Distance Matrix API.
 */

export type LatLng = { lat: number; lng: number };

function getApiKey(): string {
  const key = process.env.GOOGLE_MAPS_API_KEY?.trim();
  if (!key) {
    throw new Error(
      "GOOGLE_MAPS_API_KEY is not configured on the server. Contact support to enable price estimates."
    );
  }
  return key;
}

export async function geocodeAddress(formattedAddress: string): Promise<LatLng> {
  const key = getApiKey();
  const address = formattedAddress.trim();
  if (!address) {
    throw new Error("Address is required for geocoding.");
  }

  const url = new URL("https://maps.googleapis.com/maps/api/geocode/json");
  url.searchParams.set("address", address);
  url.searchParams.set("key", key);

  const res = await fetch(url.toString());
  if (!res.ok) {
    throw new Error("Geocoding request failed. Try again later.");
  }

  const data = (await res.json()) as {
    status: string;
    results?: { geometry: { location: { lat: number; lng: number } } }[];
    error_message?: string;
  };

  if (data.status === "ZERO_RESULTS" || !data.results?.length) {
    throw new Error(`Could not find location for address: ${address}`);
  }
  if (data.status !== "OK") {
    throw new Error(data.error_message || `Geocoding failed (${data.status}).`);
  }

  const loc = data.results[0].geometry.location;
  return { lat: loc.lat, lng: loc.lng };
}

export async function drivingDistanceMeters(origin: LatLng, destination: LatLng): Promise<number> {
  const key = getApiKey();

  const url = new URL("https://maps.googleapis.com/maps/api/distancematrix/json");
  url.searchParams.set("origins", `${origin.lat},${origin.lng}`);
  url.searchParams.set("destinations", `${destination.lat},${destination.lng}`);
  url.searchParams.set("mode", "driving");
  url.searchParams.set("key", key);

  const res = await fetch(url.toString());
  if (!res.ok) {
    throw new Error("Distance calculation request failed. Try again later.");
  }

  const data = (await res.json()) as {
    status: string;
    rows?: { elements: { status: string; distance?: { value: number }; duration?: { value: number } }[] }[];
    error_message?: string;
  };

  if (data.status !== "OK") {
    throw new Error(data.error_message || `Distance Matrix failed (${data.status}).`);
  }

  const element = data.rows?.[0]?.elements?.[0];
  if (!element || element.status !== "OK" || element.distance?.value == null) {
    throw new Error("Could not calculate driving distance between sender and recipient.");
  }

  return element.distance.value;
}
