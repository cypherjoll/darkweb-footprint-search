import type { SourceDescriptor, SourceId } from "../types.js";
import { FixtureProvider, FIXTURE_DESCRIPTOR } from "./fixture.js";
import {
  OnionSearchEngineProvider,
  ONION_SEARCH_ENGINE_DESCRIPTOR,
} from "./onion-search-engine.js";
import type { SearchProvider } from "./provider.js";

const AHMIA_MANUAL_DESCRIPTOR: SourceDescriptor = {
  id: "ahmia-manual",
  name: "Ahmia (manual only)",
  mode: "manual",
  automated: false,
  requires_api_key: false,
  requires_tor: false,
  enabled_by_default: false,
  description:
    "Listed for operator awareness; the CLI sends no automated requests to Ahmia.",
  documentation_url: "https://ahmia.fi/terms/",
  note: "Ahmia's terms prohibit scraping or replication without permission and robots.txt disallows /search/.",
};

export function sourceDescriptors(): SourceDescriptor[] {
  return [
    ONION_SEARCH_ENGINE_DESCRIPTOR,
    FIXTURE_DESCRIPTOR,
    AHMIA_MANUAL_DESCRIPTOR,
  ];
}

export function createProvider(id: string): SearchProvider | undefined {
  if (id === "fixture") return new FixtureProvider();
  if (id === "onionsearchengine") return new OnionSearchEngineProvider();
  return undefined;
}

export function isSourceId(value: string): value is SourceId {
  return value === "fixture" || value === "onionsearchengine";
}
