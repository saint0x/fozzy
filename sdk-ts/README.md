# fozzy-sdk

TypeScript SDK for the `fozzy` Rust CLI.

- Thin wrapper around the binary (no engine logic in TS)
- Full command parity for `init/test/run/fuzz/explore/replay/trace/shrink/corpus/artifacts/report/memory/map/doctor/ci/env/version/usage/schema/validate/full`
- Streaming helper for long-running commands
- Scenario builder helpers for `steps` and `distributed` scenario JSON
- Strict type-safe build with generated declaration file (`dist/index.d.ts`)

## Install

```bash
npm install fozzy-sdk
```

`fozzy-sdk` ships types via `types` export and generates `dist/index.d.ts` at build/prepack.

## Quick Start

```ts
import { Fozzy } from "fozzy-sdk";

const fx = new Fozzy({ cwd: process.cwd(), json: true });

const run = await fx.run("tests/example.fozzy.json", { det: true, seed: 123 });
console.log(run.status, run.identity.runId);

const topo = await fx.mapSuites({
  root: ".",
  scenarioRoot: "tests",
  minRisk: 60,
  profile: "pedantic",
});
console.log(topo);
```

## Streaming

```ts
for await (const chunk of fx.stream(["fuzz", "fn:utf8", "--time", "10s"])) {
  process.stdout.write(`[${chunk.source}] ${chunk.chunk}`);
}
```

## Builders

```ts
import { ScenarioBuilder, DistributedScenarioBuilder } from "fozzy-sdk";

await new ScenarioBuilder("simple")
  .setKv("k", "v")
  .getKvAssert("k", "v")
  .write("tests/simple.fozzy.json");

await new DistributedScenarioBuilder("dist")
  .withNodeCount(3)
  .step({ type: "client_put", node: "n0", key: "x", value: "1" })
  .invariant({ type: "kv_all_equal", key: "x" })
  .write("tests/dist.fozzy.json");
```
