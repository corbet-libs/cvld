import createClient from "openapi-fetch";
import type { paths } from "./schema";
export const client = (baseUrl: string, session?: string) => createClient<paths>({
  baseUrl,
  headers: session ? { Authorization: `Bearer ${session}` } : {},
});
export type { paths, components, operations } from "./schema";
