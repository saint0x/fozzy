/* eslint-disable @typescript-eslint/no-unused-vars */
/**
 * Fozzy TS SDK (wrapper around the `fozzy` binary).
 *
 * Design goals:
 * - One unified surface: test + assertions + mocks + fuzz + explore + replay + shrink.
 * - Determinism-first: seed + trace => exact reproduction.
 * - Batteries included: fixtures, capability mocks, reporters, artifacts.
 *
 * NOTE: This SDK does not implement the engine; it invokes the Rust binary.
 */

import { spawn } from "node:child_process";
import * as path from "node:path";
import * as fs from "node:fs/promises";

///////////////////////////
// Shared Types
///////////////////////////

export type LogLevel = "trace" | "debug" | "info" | "warn" | "error";
export type Duration = `${number}ms` | `${number}s` | `${number}m` | `${number}h`;
export type Reporter = "pretty" | "json" | "junit" | "html";

export type RunMode = "test" | "fuzz" | "explore" | "run";

export type ScheduleStrategy =
  | "fifo"
  | "random"
  | "pct" // probabilistic concurrency testing
  | "dfs"
  | "bfs"
  | "coverage-guided";

export type FuzzMode = "coverage" | "property";

export type ArtifactKind =
  | "trace"
  | "timeline"
  | "events"
  | "report"
  | "min-repro"
  | "logs"
  | "corpus";

export type ExitStatus = "pass" | "fail" | "error" | "timeout" | "crash";

export interface FozzyBinOptions {
  /** Path to fozzy binary. Defaults to `fozzy` on PATH. */
  bin?: string;
  /** Working directory for execution. */
  cwd?: string;
  /** Path to config file. */
  config?: string;
  /** Default log level. */
  logLevel?: LogLevel;
  /** Disable color output. */
  noColor?: boolean;
  /** Force machine-readable output by default. */
  json?: boolean;
  /** Additional environment variables. */
  env?: Record<string, string | undefined>;
}

export interface RunIdentity {
  runId: string;          // stable run id from the engine
  seed: number;           // seed used
  tracePath?: string;     // if recorded
  reportPath?: string;    // if emitted
  artifactsDir?: string;  // if emitted
}

export interface RunSummary {
  status: ExitStatus;
  mode: RunMode;
  identity: RunIdentity;
  startedAt: string; // ISO
  finishedAt: string; // ISO
  durationMs: number;
  tests?: { passed: number; failed: number; skipped: number };
  findings?: Array<{
    kind: "assertion" | "panic" | "hang" | "invariant" | "checker";
    title: string;
    message: string;
    location?: { file?: string; line?: number; col?: number };
  }>;
}

export interface RunResult {
  summary: RunSummary;
  /** Raw engine JSON (if enabled) for power users. */
  raw?: unknown;
  /** Load artifacts after run completes. */
  artifacts(): Promise<Artifacts>;
  /** Convenience: throw if not pass. */
  assertPass(): void;
}

///////////////////////////
// CLI Invocation Layer
///////////////////////////

export class Fozzy {
  private readonly opt: Required<FozzyBinOptions>;

  constructor(opt: FozzyBinOptions = {}) {
    this.opt = {
      bin: opt.bin ?? "fozzy",
      cwd: opt.cwd ?? process.cwd(),
      config: opt.config ?? path.join(opt.cwd ?? process.cwd(), "fozzy.toml"),
      logLevel: opt.logLevel ?? "info",
      noColor: opt.noColor ?? false,
      json: opt.json ?? true,
      env: opt.env ?? {},
    };
  }

  /** Low-level: invoke raw CLI args. */
  async exec(args: string[], io: ExecIO = {}): Promise<ExecResult> {
    const fullArgs = this.withGlobalFlags(args);
    return await spawnCollect(this.opt.bin, fullArgs, {
      cwd: this.opt.cwd,
      env: { ...process.env, ...this.opt.env },
      stdin: io.stdin,
      onStdout: io.onStdout,
      onStderr: io.onStderr,
    });
  }

  /** `fozzy init` */
  async init(opts: InitOptions = {}): Promise<void> {
    const args = ["init"];
    if (opts.force) args.push("--force");
    if (opts.template) args.push("--template", opts.template);
    await this.execOrThrow(args, { mode: "init" });
  }

  /** Run normal tests (`fozzy test`) */
  async test(opts: TestOptions = {}): Promise<RunResult> {
    const args = ["test"];
    if (opts.globs?.length) args.push(...opts.globs);
    pushIf(args, opts.det, "--det");
    pushKV(args, "--seed", opts.seed);
    pushKV(args, "--jobs", opts.jobs);
    pushKV(args, "--timeout", opts.timeout);
    pushKV(args, "--filter", opts.filter);
    pushKV(args, "--reporter", opts.reporter);
    pushKV(args, "--record", opts.recordTraceTo);
    pushIf(args, opts.failFast, "--fail-fast");
    return await this.execRun(args, "test");
  }

  /** Run a single scenario (`fozzy run`) */
  async runScenario(scenarioPath: string, opts: RunScenarioOptions = {}): Promise<RunResult> {
    const args = ["run", scenarioPath];
    pushIf(args, opts.det, "--det");
    pushKV(args, "--seed", opts.seed);
    pushKV(args, "--timeout", opts.timeout);
    pushKV(args, "--reporter", opts.reporter);
    pushKV(args, "--record", opts.recordTraceTo);
    return await this.execRun(args, "run");
  }

  /** Coverage-guided or property fuzzing (`fozzy fuzz`) */
  async fuzz(target: FuzzTarget, opts: FuzzOptions = {}): Promise<RunResult> {
    const args = ["fuzz", targetToCli(target)];
    pushKV(args, "--mode", opts.mode ?? "coverage");
    pushKV(args, "--seed", opts.seed);
    pushKV(args, "--time", opts.time);
    pushKV(args, "--runs", opts.runs);
    pushKV(args, "--max-input", opts.maxInputBytes);
    pushKV(args, "--corpus", opts.corpusDir);
    pushKV(args, "--mutator", opts.mutator);
    pushIf(args, opts.shrink, "--shrink");
    pushKV(args, "--record", opts.recordTraceTo);
    pushKV(args, "--reporter", opts.reporter);
    pushIf(args, opts.crashOnly, "--crash-only");
    pushIf(args, opts.minimize, "--minimize");
    return await this.execRun(args, "fuzz");
  }

  /** Distributed deterministic exploration (`fozzy explore`) */
  async explore(scenarioPath: string, opts: ExploreOptions = {}): Promise<RunResult> {
    const args = ["explore", scenarioPath];
    pushKV(args, "--seed", opts.seed);
    pushKV(args, "--time", opts.time);
    pushKV(args, "--steps", opts.steps);
    pushKV(args, "--nodes", opts.nodes);
    pushKV(args, "--faults", opts.faults);
    pushKV(args, "--schedule", opts.schedule);
    pushKV(args, "--checker", opts.checker);
    pushKV(args, "--record", opts.recordTraceTo);
    pushIf(args, opts.shrink, "--shrink");
    pushIf(args, opts.minimize, "--minimize");
    pushKV(args, "--reporter", opts.reporter);
    return await this.execRun(args, "explore");
  }

  /** Replay a recorded trace (`fozzy replay`) */
  async replay(tracePath: string, opts: ReplayOptions = {}): Promise<RunResult> {
    const args = ["replay", tracePath];
    pushIf(args, opts.step, "--step");
    pushKV(args, "--until", opts.until);
    pushIf(args, opts.dumpEvents, "--dump-events");
    pushKV(args, "--reporter", opts.reporter);
    return await this.execRun(args, "replay");
  }

  /** Shrink a failing run (`fozzy shrink`) */
  async shrink(tracePath: string, opts: ShrinkOptions = {}): Promise<{
    outTracePath: string;
    result: RunResult;
  }> {
    const out = opts.outTracePath ?? tracePath.replace(/\.fozzy$/, "") + ".min.fozzy";
    const args = ["shrink", tracePath, "--out", out];
    pushKV(args, "--budget", opts.budget);
    pushIf(args, opts.aggressive, "--aggressive");
    pushKV(args, "--minimize", opts.minimize);
    const res = await this.execRun(args, "run");
    return { outTracePath: out, result: res };
  }

  /** Corpus ops (`fozzy corpus ...`) */
  corpus(dir: string): Corpus {
    return new Corpus(this, dir);
  }

  /** Artifacts ops (`fozzy artifacts ...`) */
  artifactsOf(runIdOrTrace: string): Artifacts {
    return new Artifacts(this, runIdOrTrace);
  }

  /** Doctor / nondeterminism detection */
  async doctor(opts: DoctorOptions = {}): Promise<DoctorReport> {
    const args = ["doctor"];
    pushIf(args, opts.deep, "--deep");
    const ex = await this.exec(args);
    return parseDoctor(ex);
  }

  /** `fozzy env` */
  async envInfo(): Promise<EnvInfo> {
    const ex = await this.exec(["env"]);
    return parseJsonOrThrow<EnvInfo>(ex.stdout);
  }

  /** `fozzy version` */
  async version(): Promise<VersionInfo> {
    const ex = await this.exec(["version"]);
    return parseJsonOrThrow<VersionInfo>(ex.stdout);
  }

  // -------- internal helpers --------

  private withGlobalFlags(args: string[]): string[] {
    const out: string[] = [];
    if (this.opt.config) out.push("--config", this.opt.config);
    if (this.opt.logLevel) out.push("--log", this.opt.logLevel);
    if (this.opt.noColor) out.push("--no-color");
    if (this.opt.json) out.push("--json");
    return [...out, ...args];
  }

  private async execOrThrow(args: string[], ctx: { mode: string }): Promise<void> {
    const ex = await this.exec(args);
    if (ex.code !== 0) {
      throw new Error(`fozzy ${ctx.mode} failed (code=${ex.code})\n${ex.stderr || ex.stdout}`);
    }
  }

  private async execRun(args: string[], mode: RunMode): Promise<RunResult> {
    const ex = await this.exec(args);
    const raw = safeParseJson(ex.stdout) ?? safeParseJson(ex.stderr);
    const summary = parseRunSummary(raw, ex, mode);
    return {
      summary,
      raw,
      artifacts: async () => new Artifacts(this, summary.identity.tracePath ?? summary.identity.runId),
      assertPass: () => {
        if (summary.status !== "pass") {
          throw new Error(`Fozzy run failed (${summary.status})\nrunId=${summary.identity.runId}\nseed=${summary.identity.seed}\ntrace=${summary.identity.tracePath ?? "n/a"}`);
        }
      },
    };
  }
}

///////////////////////////
// Options: CLI-equivalent
///////////////////////////

export interface InitOptions {
  force?: boolean;
  template?: "ts" | "rust" | "minimal";
}

export interface MemoryOptions {
  memTrack?: boolean;
  memLimitMb?: number;
  memFailAfter?: number;
  failOnLeak?: boolean;
  leakBudget?: number;
  memArtifacts?: boolean;
}

export interface TestOptions extends MemoryOptions {
  globs?: string[];
  det?: boolean;
  seed?: number;
  jobs?: number;
  timeout?: Duration;
  filter?: string;
  reporter?: Reporter;
  recordTraceTo?: string; // path for trace.fozzy
  failFast?: boolean;
}

export interface RunScenarioOptions extends MemoryOptions {
  det?: boolean;
  seed?: number;
  timeout?: Duration;
  reporter?: Reporter;
  recordTraceTo?: string;
}

export type FuzzTarget =
  | { kind: "function"; id: string }     // e.g. "pkg.module:fnName"
  | { kind: "http"; route: string }      // e.g. "POST /v1/payments"
  | { kind: "grpc"; method: string }     // e.g. "svc.Payments/Charge"
  | { kind: "scenario"; path: string };  // fuzz a whole scenario

export interface FuzzOptions {
  mode?: FuzzMode;
  seed?: number;
  time?: Duration;
  runs?: number;
  maxInputBytes?: number;
  corpusDir?: string;
  mutator?: string;       // "bytes", "json", "protobuf", "http", "custom:..."
  shrink?: boolean;
  recordTraceTo?: string;
  reporter?: Reporter;
  crashOnly?: boolean;
  minimize?: boolean;
  memTrack?: boolean;
  memLimitMb?: number;
  memFailAfter?: number;
  failOnLeak?: boolean;
  leakBudget?: number;
  memArtifacts?: boolean;
}

export interface ExploreOptions extends MemoryOptions {
  seed?: number;
  time?: Duration;
  steps?: number;
  nodes?: number;
  faults?: string;        // preset name or file path
  schedule?: ScheduleStrategy;
  checker?: string;       // "linearizability", "refinement", "invariants"
  recordTraceTo?: string;
  shrink?: boolean;
  minimize?: boolean;
  reporter?: Reporter;
}

export interface ReplayOptions {
  step?: boolean;
  until?: Duration;
  dumpEvents?: boolean;
  reporter?: Reporter;
}

export interface ShrinkOptions {
  outTracePath?: string;
  budget?: Duration;
  aggressive?: boolean;
  minimize?: "input" | "schedule" | "faults" | "all";
}

export interface DoctorOptions {
  deep?: boolean;
}

///////////////////////////
// Higher-level SDK: Test DSL
///////////////////////////

/**
 * The SDK side “test DSL” is mainly:
 * - authoring structure
 * - generating a Scenario IR JSON
 * - then running via fozzy binary
 *
 * In v1 you can keep this minimal: users can just write normal tests,
 * and use the wrapper for running modes. But if you want “one DSL”,
 * this is the shape.
 */

export interface Ctx {
  seed(): number;

  // Capabilities (mockable/deterministic)
  time: TimeCap;
  rand: RandCap;
  net: NetCap;
  fs: FsCap;
  http: HttpCap;
  proc: ProcCap;
  kv: KvCap; // optional sample higher-level fixture

  // Assertions / expectations (works everywhere)
  assert: Assert;

  // Lifecycle + tracing
  trace: TraceCap;
  invariant(name: string, fn: () => boolean | Promise<boolean>): void;
}

export interface Assert {
  ok(cond: unknown, msg?: string): void;
  eq<T>(a: T, b: T, msg?: string): void;
  ne<T>(a: T, b: T, msg?: string): void;
  match(str: string, re: RegExp, msg?: string): void;

  throws(fn: () => unknown, msg?: string): void;
  rejects(p: Promise<unknown>, msg?: string): Promise<void>;

  eventually(fn: () => boolean | Promise<boolean>, opts?: { within?: Duration; poll?: Duration; msg?: string }): Promise<void>;
  never(fn: () => boolean | Promise<boolean>, opts?: { within?: Duration; poll?: Duration; msg?: string }): Promise<void>;
}

export interface TimeCap {
  nowMs(): number;
  sleep(d: Duration): Promise<void>;
  advance(d: Duration): Promise<void>; // deterministic mode only
  freeze(at?: number): Promise<void>;
  unfreeze(): Promise<void>;
}

export interface RandCap {
  u64(): bigint;
  int(min: number, max: number): number;
  bytes(n: number): Uint8Array;
  uuid(): string;
  choose<T>(arr: readonly T[]): T;
}

export interface NetCap {
  // Deterministic distributed network controls
  partition(a: string, b: string): Promise<void>;
  heal(a: string, b: string): Promise<void>;
  setLatency(ms: number | { min: number; max: number }): Promise<void>;
  setDropRate(rate: number): Promise<void>;
  setReorder(enabled: boolean): Promise<void>;
  setDuplicate(enabled: boolean): Promise<void>;
}

export interface FsCap {
  tempDir(prefix?: string): Promise<string>;
  writeFile(p: string, data: Uint8Array | string): Promise<void>;
  readFile(p: string): Promise<Uint8Array>;
  crashNow(): Promise<void>; // simulate crash semantics if enabled
  snapshot(name: string): Promise<void>;
  restore(name: string): Promise<void>;
}

export interface HttpCap {
  /**
   * Scriptable mocking. Can be:
   * - pure fake routes
   * - record/replay contracts
   */
  when(method: string, path: string): HttpMockRule;
  record(baseUrl: string, outCassette: string): Promise<void>;
  replay(baseUrl: string, cassette: string): Promise<void>;
}

export interface HttpMockRule {
  thenStatus(code: number): HttpMockRule;
  thenJson(obj: unknown): HttpMockRule;
  thenBody(body: string | Uint8Array): HttpMockRule;
  thenDelay(d: Duration): HttpMockRule;
  thenError(name: string, msg?: string): HttpMockRule;
  times(n: number): HttpMockRule;
}

export interface ProcCap {
  spawn(cmd: string, args?: string[], opts?: { cwd?: string; env?: Record<string, string> }): Promise<ProcHandle>;
  kill(pid: number, signal?: "SIGKILL" | "SIGTERM"): Promise<void>;
}

export interface ProcHandle {
  pid: number;
  stdout(): AsyncIterable<Uint8Array>;
  stderr(): AsyncIterable<Uint8Array>;
  wait(): Promise<{ code: number; signal?: string }>;
}

export interface KvCap {
  // Example higher-level fixture for demos
  startNode(name: string, opts?: { port?: number }): Promise<void>;
  stopNode(name: string): Promise<void>;
  put(node: string, key: string, value: string): Promise<void>;
  get(node: string, key: string): Promise<string | null>;
}

export interface TraceCap {
  event(name: string, fields?: Record<string, unknown>): void;
  span<T>(name: string, fn: () => Promise<T>, fields?: Record<string, unknown>): Promise<T>;
  attach(name: string, data: Uint8Array | string): void; // artifact
}

///////////////////////////
// Scenario / Suite authoring
///////////////////////////

export type TestFn = (ctx: Ctx) => void | Promise<void>;

export interface SuiteDef {
  name: string;
  beforeEach?: TestFn;
  afterEach?: TestFn;
  tests: Array<{ name: string; fn: TestFn; tags?: string[] }>;
}

export class SuiteBuilder {
  private def: SuiteDef;

  constructor(name: string) {
    this.def = { name, tests: [] };
  }

  beforeEach(fn: TestFn): this {
    this.def.beforeEach = fn;
    return this;
  }

  afterEach(fn: TestFn): this {
    this.def.afterEach = fn;
    return this;
  }

  test(name: string, fn: TestFn, tags?: string[]): this {
    this.def.tests.push({ name, fn, tags });
    return this;
  }

  build(): SuiteDef {
    return this.def;
  }
}

/**
 * In practice, Suite/Senario authoring compiles to JSON IR that the binary runs.
 * The TS SDK can provide helper methods, but the real execution happens in Rust.
 */
export interface ScenarioIR {
  version: 1;
  name: string;
  suites: SuiteDef[];
  capabilities?: Record<string, unknown>;
  faults?: Record<string, unknown>;
  checkers?: string[];
}

export class ScenarioBuilder {
  private ir: ScenarioIR;

  constructor(name: string) {
    this.ir = { version: 1, name, suites: [] };
  }

  suite(s: SuiteDef): this {
    this.ir.suites.push(s);
    return this;
  }

  faults(f: Record<string, unknown>): this {
    this.ir.faults = f;
    return this;
  }

  checkers(...names: string[]): this {
    this.ir.checkers = names;
    return this;
  }

  capabilities(c: Record<string, unknown>): this {
    this.ir.capabilities = c;
    return this;
  }

  toIR(): ScenarioIR {
    return this.ir;
  }

  async writeTo(filePath: string): Promise<void> {
    await fs.writeFile(filePath, JSON.stringify(this.ir, null, 2), "utf8");
  }
}

///////////////////////////
// Corpus + Artifacts convenience APIs
///////////////////////////

export class Corpus {
  constructor(private fx: Fozzy, private dir: string) {}

  async list(): Promise<string[]> {
    const ex = await this.fx.exec(["corpus", "list", this.dir]);
    return parseJsonOrThrow<string[]>(ex.stdout);
  }

  async add(file: string): Promise<void> {
    await this.fx.execOrThrow(["corpus", "add", this.dir, file], { mode: "corpus add" });
  }

  async minimize(opts: { budget?: Duration } = {}): Promise<void> {
    const args = ["corpus", "minimize", this.dir];
    pushKV(args, "--budget", opts.budget);
    await this.fx.execOrThrow(args, { mode: "corpus minimize" });
  }

  async exportZip(outZip: string): Promise<void> {
    await this.fx.execOrThrow(["corpus", "export", this.dir, "--out", outZip], { mode: "corpus export" });
  }

  async importZip(zip: string): Promise<void> {
    await this.fx.execOrThrow(["corpus", "import", zip, "--out", this.dir], { mode: "corpus import" });
  }
}

export class Artifacts {
  constructor(private fx: Fozzy, private runIdOrTrace: string) {}

  async list(): Promise<Array<{ kind: ArtifactKind; path: string; sizeBytes?: number }>> {
    const ex = await this.fx.exec(["artifacts", "ls", this.runIdOrTrace]);
    return parseJsonOrThrow(ex.stdout);
  }

  async export(out: string): Promise<void> {
    await this.fx.execOrThrow(["artifacts", "export", this.runIdOrTrace, "--out", out], { mode: "artifacts export" });
  }

  async readReport(): Promise<RunSummary> {
    const ex = await this.fx.exec(["report", "show", this.runIdOrTrace, "--format", "json"]);
    return parseJsonOrThrow(ex.stdout);
  }
}

///////////////////////////
// Doctor / Env / Version
///////////////////////////

export interface DoctorReport {
  ok: boolean;
  issues: Array<{ code: string; message: string; hint?: string }>;
  nondeterminismSignals?: Array<{ source: string; detail: string }>;
}

export interface EnvInfo {
  os: string;
  arch: string;
  fozzy: { version: string; commit?: string };
  capabilities: Record<string, { backend: string; deterministic: boolean }>;
}

export interface VersionInfo {
  version: string;
  commit?: string;
  buildDate?: string;
}

///////////////////////////
// Example usage: unified surface
///////////////////////////

async function example_full_stack() {
  const fozzy = new Fozzy({
    json: true,
    logLevel: "info",
  });

  // 1) Author a suite (optional if you already use native test files)
  const suite = new SuiteBuilder("payments")
    .beforeEach(async (ctx) => {
      ctx.trace.event("setup");
      // ctx.http.when("POST", "/charge").thenStatus(200); // etc
    })
    .test("idempotency", async (ctx) => {
      const id = ctx.rand.uuid();
      ctx.assert.ok(id.length > 0);

      // Example “simple test framework” assertion style:
      ctx.assert.eq(1 + 1, 2);

      // Example “perfect mock”
      ctx.http.when("POST", "/charge").thenStatus(200).times(1);

      // Example “time control”
      await ctx.time.advance("250ms");

      // Example invariants
      ctx.invariant("balance_non_negative", () => true);
    })
    .build();

  const scenario = new ScenarioBuilder("payments-scenario")
    .suite(suite)
    .faults({
      network: { reorder: true, dropRate: 0.01, partition: true },
      process: { kill: true, restart: true },
    })
    .checkers("invariants")
    .toIR();

  const scenarioPath = path.join(process.cwd(), "fozzy.scenario.json");
  await fs.writeFile(scenarioPath, JSON.stringify(scenario, null, 2), "utf8");

  // 2) Run normal tests (fast)
  const testRes = await fozzy.test({ globs: ["tests/**/*.fozzy.ts"], reporter: "json" });
  testRes.assertPass();

  // 3) Run deterministic distributed exploration
  const exploreRes = await fozzy.explore(scenarioPath, {
    seed: 1337,
    time: "30s",
    nodes: 5,
    schedule: "pct",
    shrink: true,
    minimize: true,
    recordTraceTo: "runs/payments-1337.fozzy",
  });

  if (exploreRes.summary.status !== "pass") {
    // 4) Replay exact failure
    const trace = exploreRes.summary.identity.tracePath!;
    await fozzy.replay(trace, { step: true, dumpEvents: true });

    // 5) Shrink to minimal reproduction
    const shrunk = await fozzy.shrink(trace, { minimize: "all", aggressive: true });
    console.log("min trace:", shrunk.outTracePath);
  }
}

///////////////////////////
// Internals: spawn + parsing
///////////////////////////

export interface ExecIO {
  stdin?: string | Uint8Array;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function spawnCollect(
  bin: string,
  args: string[],
  opts: {
    cwd: string;
    env: Record<string, string | undefined>;
    stdin?: string | Uint8Array;
    onStdout?: (chunk: string) => void;
    onStderr?: (chunk: string) => void;
  }
): Promise<ExecResult> {
  return await new Promise((resolve, reject) => {
    const p = spawn(bin, args, {
      cwd: opts.cwd,
      env: opts.env as Record<string, string>,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let out = "";
    let err = "";

    p.stdout.setEncoding("utf8");
    p.stderr.setEncoding("utf8");

    p.stdout.on("data", (d: string) => {
      out += d;
      opts.onStdout?.(d);
    });

    p.stderr.on("data", (d: string) => {
      err += d;
      opts.onStderr?.(d);
    });

    p.on("error", reject);

    p.on("close", (code) => {
      resolve({ code: code ?? 1, stdout: out.trim(), stderr: err.trim() });
    });

    if (opts.stdin != null) {
      p.stdin.write(opts.stdin);
    }
    p.stdin.end();
  });
}

function parseRunSummary(raw: any, ex: ExecResult, mode: RunMode): RunSummary {
  // Expect engine JSON like:
  // { status, runId, seed, tracePath, reportPath, artifactsDir, ... }
  if (!raw || typeof raw !== "object") {
    return {
      status: ex.code === 0 ? "pass" : "error",
      mode,
      identity: { runId: "unknown", seed: 0 },
      startedAt: new Date().toISOString(),
      finishedAt: new Date().toISOString(),
      durationMs: 0,
      findings: ex.code === 0 ? [] : [{ kind: "checker", title: "Non-JSON output", message: ex.stderr || ex.stdout }],
    };
  }

  const seed = typeof raw.seed === "number" ? raw.seed : 0;

  return {
    status: raw.status ?? (ex.code === 0 ? "pass" : "error"),
    mode,
    identity: {
      runId: raw.runId ?? raw.run_id ?? "unknown",
      seed,
      tracePath: raw.tracePath ?? raw.trace_path,
      reportPath: raw.reportPath ?? raw.report_path,
      artifactsDir: raw.artifactsDir ?? raw.artifacts_dir,
    },
    startedAt: raw.startedAt ?? raw.started_at ?? new Date().toISOString(),
    finishedAt: raw.finishedAt ?? raw.finished_at ?? new Date().toISOString(),
    durationMs: raw.durationMs ?? raw.duration_ms ?? 0,
    tests: raw.tests,
    findings: raw.findings ?? [],
  };
}

function parseDoctor(ex: ExecResult): DoctorReport {
  const j = safeParseJson(ex.stdout) ?? safeParseJson(ex.stderr);
  if (!j) {
    return { ok: ex.code === 0, issues: [{ code: "doctor_non_json", message: ex.stderr || ex.stdout }] };
  }
  return j as DoctorReport;
}

function safeParseJson(s: string): any | null {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

function parseJsonOrThrow<T>(s: string): T {
  const j = safeParseJson(s);
  if (!j) throw new Error(`Expected JSON, got:\n${s}`);
  return j as T;
}

function pushIf(args: string[], cond: unknown, flag: string) {
  if (cond) args.push(flag);
}
function pushKV(args: string[], k: string, v: unknown) {
  if (v === undefined || v === null) return;
  args.push(k, String(v));
}
function targetToCli(t: FuzzTarget): string {
  switch (t.kind) {
    case "function": return `fn:${t.id}`;
    case "http": return `http:${t.route}`;
    case "grpc": return `grpc:${t.method}`;
    case "scenario": return `scenario:${t.path}`;
  }
}

///////////////////////////
// (Optional) “native rust” bypass notes
///////////////////////////
//
// - TS SDK wraps binary for determinism + consistent engine behavior.
// - Native Rust SDK can link directly and avoid process spawn overhead.
// - All other language SDKs mirror TS: thin client, engine in Rust.
