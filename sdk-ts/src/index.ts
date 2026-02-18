import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";

export type LogLevel = "trace" | "debug" | "info" | "warn" | "error";
export type Duration = `${number}ms` | `${number}s` | `${number}m` | `${number}h`;
export type Reporter = "pretty" | "json" | "junit" | "html";
export type ExitStatus = "pass" | "fail" | "error" | "timeout" | "crash";
export type RunMode = "test" | "run" | "fuzz" | "explore" | "replay";

export interface FozzyOptions {
  bin?: string;
  cwd?: string;
  config?: string;
  log?: LogLevel;
  json?: boolean;
  noColor?: boolean;
  env?: Record<string, string | undefined>;
}

export interface RunIdentity {
  runId: string;
  seed: number;
  tracePath?: string;
  reportPath?: string;
  artifactsDir?: string;
}

export interface RunSummary {
  status: ExitStatus;
  mode: RunMode;
  identity: RunIdentity;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  tests?: { passed: number; failed: number; skipped: number };
  findings?: Array<{ kind: string; title: string; message: string }>;
}

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type StreamChunk = {
  source: "stdout" | "stderr";
  chunk: string;
};

export interface ExecIO {
  stdin?: string;
  onStdout?: (chunk: string) => void;
  onStderr?: (chunk: string) => void;
}

export interface TestOptions {
  globs?: string[];
  det?: boolean;
  seed?: number;
  jobs?: number;
  timeout?: Duration;
  filter?: string;
  reporter?: Reporter;
  record?: string;
  failFast?: boolean;
}

export interface RunOptions {
  det?: boolean;
  seed?: number;
  timeout?: Duration;
  reporter?: Reporter;
  record?: string;
}

export type FuzzMode = "coverage" | "property";
export interface FuzzOptions {
  mode?: FuzzMode;
  seed?: number;
  time?: Duration;
  runs?: number;
  maxInput?: number;
  corpus?: string;
  mutator?: string;
  shrink?: boolean;
  record?: string;
  reporter?: Reporter;
  crashOnly?: boolean;
  minimize?: boolean;
}

export type Schedule = "fifo" | "bfs" | "dfs" | "random" | "pct" | "coverage_guided";
export interface ExploreOptions {
  seed?: number;
  time?: Duration;
  steps?: number;
  nodes?: number;
  faults?: string;
  schedule?: Schedule;
  checker?: string;
  record?: string;
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
  out?: string;
  budget?: Duration;
  aggressive?: boolean;
  minimize?: "input" | "schedule" | "faults" | "all";
}

export interface DoctorOptions {
  deep?: boolean;
  scenario?: string;
  runs?: number;
  seed?: number;
}

export interface ReportShowOptions {
  format?: Reporter;
}

export class Fozzy {
  private readonly opt: Required<FozzyOptions>;

  constructor(opt: FozzyOptions = {}) {
    this.opt = {
      bin: opt.bin ?? "fozzy",
      cwd: opt.cwd ?? process.cwd(),
      config: opt.config ?? "fozzy.toml",
      log: opt.log ?? "info",
      json: opt.json ?? true,
      noColor: opt.noColor ?? false,
      env: opt.env ?? {},
    };
  }

  async exec(args: string[], io: ExecIO = {}): Promise<ExecResult> {
    const fullArgs = this.globalArgs().concat(args);
    return await spawnCollect(this.opt.bin, fullArgs, {
      cwd: this.opt.cwd,
      env: { ...process.env, ...this.opt.env },
      stdin: io.stdin,
      onStdout: io.onStdout,
      onStderr: io.onStderr,
    });
  }

  async *stream(args: string[], io: { stdin?: string } = {}): AsyncGenerator<StreamChunk> {
    const fullArgs = this.globalArgs().concat(args);
    const cp = spawn(this.opt.bin, fullArgs, {
      cwd: this.opt.cwd,
      env: { ...process.env, ...this.opt.env },
      stdio: "pipe",
    });
    if (io.stdin) cp.stdin.write(io.stdin);
    cp.stdin.end();

    const queue: StreamChunk[] = [];
    let done = false;
    let resolveWait: (() => void) | undefined;

    const push = (item: StreamChunk): void => {
      queue.push(item);
      if (resolveWait) {
        const r = resolveWait;
        resolveWait = undefined;
        r();
      }
    };

    cp.stdout.on("data", (b: Buffer) => push({ source: "stdout", chunk: b.toString("utf8") }));
    cp.stderr.on("data", (b: Buffer) => push({ source: "stderr", chunk: b.toString("utf8") }));
    cp.on("close", () => {
      done = true;
      if (resolveWait) {
        const r = resolveWait;
        resolveWait = undefined;
        r();
      }
    });

    while (!done || queue.length > 0) {
      if (queue.length === 0) {
        await new Promise<void>((resolve) => {
          resolveWait = resolve;
        });
      }
      while (queue.length > 0) {
        const item = queue.shift();
        if (item) yield item;
      }
    }
  }

  async init(opts: { force?: boolean; template?: "ts" | "rust" | "minimal" } = {}): Promise<void> {
    const args = ["init"];
    if (opts.force) args.push("--force");
    if (opts.template) args.push("--template", opts.template);
    await this.execOrThrow(args);
  }

  async usage(): Promise<unknown> {
    const ex = await this.execOrThrow(["usage"]);
    return parseJson(ex.stdout);
  }

  async test(opts: TestOptions = {}): Promise<RunSummary> {
    const args = ["test"];
    if (opts.globs) args.push(...opts.globs);
    flag(args, opts.det, "--det");
    kv(args, "--seed", opts.seed);
    kv(args, "--jobs", opts.jobs);
    kv(args, "--timeout", opts.timeout);
    kv(args, "--filter", opts.filter);
    kv(args, "--reporter", opts.reporter);
    kv(args, "--record", opts.record);
    flag(args, opts.failFast, "--fail-fast");
    return await this.execRun(args);
  }

  async run(scenario: string, opts: RunOptions = {}): Promise<RunSummary> {
    const args = ["run", scenario];
    flag(args, opts.det, "--det");
    kv(args, "--seed", opts.seed);
    kv(args, "--timeout", opts.timeout);
    kv(args, "--reporter", opts.reporter);
    kv(args, "--record", opts.record);
    return await this.execRun(args);
  }

  async fuzz(target: string, opts: FuzzOptions = {}): Promise<RunSummary> {
    const args = ["fuzz", target];
    kv(args, "--mode", opts.mode);
    kv(args, "--seed", opts.seed);
    kv(args, "--time", opts.time);
    kv(args, "--runs", opts.runs);
    kv(args, "--max-input", opts.maxInput);
    kv(args, "--corpus", opts.corpus);
    kv(args, "--mutator", opts.mutator);
    flag(args, opts.shrink, "--shrink");
    kv(args, "--record", opts.record);
    kv(args, "--reporter", opts.reporter);
    flag(args, opts.crashOnly, "--crash-only");
    flag(args, opts.minimize, "--minimize");
    return await this.execRun(args);
  }

  async explore(scenario: string, opts: ExploreOptions = {}): Promise<RunSummary> {
    const args = ["explore", scenario];
    kv(args, "--seed", opts.seed);
    kv(args, "--time", opts.time);
    kv(args, "--steps", opts.steps);
    kv(args, "--nodes", opts.nodes);
    kv(args, "--faults", opts.faults);
    kv(args, "--schedule", opts.schedule);
    kv(args, "--checker", opts.checker);
    kv(args, "--record", opts.record);
    flag(args, opts.shrink, "--shrink");
    flag(args, opts.minimize, "--minimize");
    kv(args, "--reporter", opts.reporter);
    return await this.execRun(args);
  }

  async replay(trace: string, opts: ReplayOptions = {}): Promise<RunSummary> {
    const args = ["replay", trace];
    flag(args, opts.step, "--step");
    kv(args, "--until", opts.until);
    flag(args, opts.dumpEvents, "--dump-events");
    kv(args, "--reporter", opts.reporter);
    return await this.execRun(args);
  }

  async shrink(trace: string, opts: ShrinkOptions = {}): Promise<RunSummary> {
    const args = ["shrink", trace];
    kv(args, "--out", opts.out);
    kv(args, "--budget", opts.budget);
    flag(args, opts.aggressive, "--aggressive");
    kv(args, "--minimize", opts.minimize);
    return await this.execRun(args);
  }

  async corpusList(dir: string): Promise<unknown> {
    return await this.execJson(["corpus", "list", dir]);
  }

  async corpusAdd(dir: string, file: string): Promise<void> {
    await this.execOrThrow(["corpus", "add", dir, file]);
  }

  async corpusMinimize(dir: string, budget?: Duration): Promise<void> {
    const args = ["corpus", "minimize", dir];
    kv(args, "--budget", budget);
    await this.execOrThrow(args);
  }

  async corpusExport(dir: string, out: string): Promise<void> {
    await this.execOrThrow(["corpus", "export", dir, "--out", out]);
  }

  async corpusImport(zip: string, out: string): Promise<void> {
    await this.execOrThrow(["corpus", "import", zip, "--out", out]);
  }

  async artifactsLs(runOrTrace: string): Promise<unknown> {
    return await this.execJson(["artifacts", "ls", runOrTrace]);
  }

  async artifactsDiff(left: string, right: string): Promise<unknown> {
    return await this.execJson(["artifacts", "diff", left, right]);
  }

  async artifactsExport(runOrTrace: string, out: string): Promise<void> {
    await this.execOrThrow(["artifacts", "export", runOrTrace, "--out", out]);
  }

  async reportShow(runOrTrace: string, opts: ReportShowOptions = {}): Promise<unknown> {
    const args = ["report", "show", runOrTrace];
    kv(args, "--format", opts.format);
    return await this.execJson(args);
  }

  async reportQuery(runOrTrace: string, jq: string): Promise<unknown> {
    return await this.execJson(["report", "query", runOrTrace, "--jq", jq]);
  }

  async reportFlaky(runs: string[]): Promise<unknown> {
    return await this.execJson(["report", "flaky", ...runs]);
  }

  async doctor(opts: DoctorOptions = {}): Promise<unknown> {
    const args = ["doctor"];
    flag(args, opts.deep, "--deep");
    kv(args, "--scenario", opts.scenario);
    kv(args, "--runs", opts.runs);
    kv(args, "--seed", opts.seed);
    return await this.execJson(args);
  }

  async env(): Promise<unknown> {
    return await this.execJson(["env"]);
  }

  async version(): Promise<unknown> {
    return await this.execJson(["version"]);
  }

  private globalArgs(): string[] {
    const args: string[] = [];
    kv(args, "--config", this.opt.config);
    kv(args, "--log", this.opt.log);
    flag(args, this.opt.noColor, "--no-color");
    flag(args, this.opt.json, "--json");
    return args;
  }

  private async execRun(args: string[]): Promise<RunSummary> {
    const ex = await this.execOrThrow(args);
    const value = parseJson(ex.stdout);
    if (!isRunSummary(value)) {
      throw new Error(`unexpected run summary JSON: ${ex.stdout}`);
    }
    return value;
  }

  private async execJson(args: string[]): Promise<unknown> {
    const ex = await this.execOrThrow(args);
    return parseJson(ex.stdout);
  }

  private async execOrThrow(args: string[]): Promise<ExecResult> {
    const ex = await this.exec(args);
    if (ex.code !== 0) {
      throw new Error(`fozzy ${args.join(" ")} failed (${ex.code})\n${ex.stderr || ex.stdout}`);
    }
    return ex;
  }
}

function kv(args: string[], key: string, value: unknown): void {
  if (value === undefined || value === null) return;
  args.push(key, String(value));
}

function flag(args: string[], enabled: unknown, key: string): void {
  if (enabled) args.push(key);
}

function parseJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    throw new Error(`invalid JSON from fozzy:\n${s}`);
  }
}

function isRunSummary(v: unknown): v is RunSummary {
  if (!v || typeof v !== "object") return false;
  const m = v as Record<string, unknown>;
  return typeof m.status === "string" && typeof m.mode === "string" && typeof m.identity === "object";
}

async function spawnCollect(
  bin: string,
  args: string[],
  opts: {
    cwd: string;
    env: Record<string, string | undefined>;
    stdin?: string;
    onStdout?: (chunk: string) => void;
    onStderr?: (chunk: string) => void;
  },
): Promise<ExecResult> {
  return await new Promise<ExecResult>((resolve, reject) => {
    const cp = spawn(bin, args, {
      cwd: opts.cwd,
      env: opts.env,
      stdio: "pipe",
    });
    let stdout = "";
    let stderr = "";

    cp.stdout.on("data", (b: Buffer) => {
      const s = b.toString("utf8");
      stdout += s;
      opts.onStdout?.(s);
    });
    cp.stderr.on("data", (b: Buffer) => {
      const s = b.toString("utf8");
      stderr += s;
      opts.onStderr?.(s);
    });
    cp.on("error", reject);
    cp.on("close", (code: number | null) => {
      resolve({ code: code ?? 1, stdout: stdout.trim(), stderr: stderr.trim() });
    });

    if (opts.stdin) cp.stdin.write(opts.stdin);
    cp.stdin.end();
  });
}

export interface ScenarioStep {
  type: string;
  [k: string]: unknown;
}

export class ScenarioBuilder {
  private readonly name: string;
  private readonly steps: ScenarioStep[] = [];

  constructor(name: string) {
    this.name = name;
  }

  step(step: ScenarioStep): this {
    this.steps.push(step);
    return this;
  }

  traceEvent(name: string, fields: Record<string, unknown> = {}): this {
    return this.step({ type: "trace_event", name, fields });
  }

  assertOk(value: boolean, msg?: string): this {
    return this.step({ type: "assert_ok", value, msg });
  }

  setKv(key: string, value: string): this {
    return this.step({ type: "set_kv", key, value });
  }

  getKvAssert(key: string, equals?: string): this {
    return this.step({ type: "get_kv_assert", key, equals });
  }

  toJSON(): { version: 1; name: string; steps: ScenarioStep[] } {
    return {
      version: 1,
      name: this.name,
      steps: this.steps,
    };
  }

  async write(path: string): Promise<void> {
    await writeFile(path, JSON.stringify(this.toJSON(), null, 2), "utf8");
  }
}

export class DistributedScenarioBuilder {
  private readonly name: string;
  private nodes?: string[];
  private nodeCount?: number;
  private readonly steps: ScenarioStep[] = [];
  private readonly invariants: ScenarioStep[] = [];

  constructor(name: string) {
    this.name = name;
  }

  withNodes(nodes: string[]): this {
    this.nodes = [...nodes];
    this.nodeCount = undefined;
    return this;
  }

  withNodeCount(count: number): this {
    this.nodeCount = count;
    this.nodes = undefined;
    return this;
  }

  step(step: ScenarioStep): this {
    this.steps.push(step);
    return this;
  }

  invariant(invariant: ScenarioStep): this {
    this.invariants.push(invariant);
    return this;
  }

  toJSON(): {
    version: 1;
    name: string;
    distributed: {
      nodes?: string[];
      node_count?: number;
      steps: ScenarioStep[];
      invariants: ScenarioStep[];
    };
  } {
    return {
      version: 1,
      name: this.name,
      distributed: {
        nodes: this.nodes,
        node_count: this.nodeCount,
        steps: this.steps,
        invariants: this.invariants,
      },
    };
  }

  async write(path: string): Promise<void> {
    await writeFile(path, JSON.stringify(this.toJSON(), null, 2), "utf8");
  }
}
