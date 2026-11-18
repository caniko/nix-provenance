// Fixture for the module eval: a script content file used as a path literal
// (`contentFile = ./fixture-procedure.ts`), so the eval proves the path keeps
// its store context. LITERAL_FIXTURE_MARKER
export async function main(): Promise<string> {
  return "fixture";
}
