import chalk from "chalk";
import gradientString from "gradient-string";
import type { SessionEntry, SessionMessage } from "../session";

type ExitSummaryInput = {
  session: SessionEntry | null;
  messages: SessionMessage[];
  model?: string;
};

type ToolCallStats = {
  total: number;
  succeeded: number;
  failed: number;
};

type TimeStats = {
  apiTimeMs: number;
  toolTimeMs: number;
};

function calculateTimeStats(messages: SessionMessage[]): TimeStats {
  let apiTimeMs = 0;
  let toolTimeMs = 0;
  let previousTime = 0;

  for (const message of messages) {
    if (message.role !== "assistant" && message.role !== "tool") {
      const t = new Date(message.createTime).getTime();
      if (t > 0) previousTime = t;
      continue;
    }

    const current = new Date(message.createTime).getTime();
    if (previousTime > 0 && current > previousTime) {
      const gap = current - previousTime;
      if (message.role === "assistant") {
        apiTimeMs += gap;
      } else {
        toolTimeMs += gap;
      }
    }
    previousTime = current;
  }

  return { apiTimeMs, toolTimeMs };
}

function countToolCalls(messages: SessionMessage[]): ToolCallStats {
  let total = 0;
  let succeeded = 0;
  let failed = 0;

  for (const message of messages) {
    if (message.role !== "tool") {
      continue;
    }
    total += 1;
    const content = message.content ?? "";
    const isError =
      /"error"\s*:\s*"/i.test(content) ||
      /"isError"\s*:\s*true/i.test(content) ||
      content.startsWith("Error:") ||
      content.startsWith("ERROR:");
    if (isError) {
      failed += 1;
    } else {
      succeeded += 1;
    }
  }

  return { total, succeeded, failed };
}

function formatDuration(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remaining = (seconds % 60).toFixed(0);
  return `${minutes}m ${remaining}s`;
}

function padRight(text: string, width: number): string {
  const visible = text.replace(/\u001b\[[0-9;]*m/g, "");
  const padding = Math.max(0, width - visible.length);
  return text + " ".repeat(padding);
}

function padLeft(text: string, width: number): string {
  const visible = text.replace(/\u001b\[[0-9;]*m/g, "");
  const padding = Math.max(0, width - visible.length);
  return " ".repeat(padding)+ text;
}

function formatNumber(n: number): string {
  return n.toLocaleString("en-US");
}

/**
 * Wrap a string of ANSI-colored text to fit within `maxWidth` visible characters per line.
 * Returns an array of lines.
 */
function wrapAnsiText(text: string, maxWidth: number): string[] {
  // Strip ANSI codes to measure visible length
  const stripAnsi = (s: string) => s.replace(/\u001b\[[0-9;]*m/g, "");
  const visibleLen = stripAnsi(text).length;
  if (visibleLen <= maxWidth) {
    return [text];
  }

  // Tokenize into ANSI-colored segments: each segment is either an escape sequence or a printable char
  const tokens: { char: string; visible: boolean }[] = [];
  const re = /\u001b\[[0-9;]*m/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    if (match.index > lastIndex) {
      for (const ch of text.slice(lastIndex, match.index)) {
        tokens.push({ char: ch, visible: true });
      }
    }
    tokens.push({ char: match[0], visible: false });
    lastIndex = re.lastIndex;
  }
  if (lastIndex < text.length) {
    for (const ch of text.slice(lastIndex)) {
      tokens.push({ char: ch, visible: true });
    }
  }

  // Group tokens into words (sequences of visible non-space chars) and spaces/separators
  type TokenWord = { text: string; visibleLen: number };
  const words: TokenWord[] = [];
  let currentWord = "";
  let currentWordLen = 0;
  let lastAnsiState = "";

  const flushWord = () => {
    if (currentWordLen > 0 || currentWord.includes("\u001b")) {
      words.push({ text: currentWord, visibleLen: currentWordLen });
    }
    currentWord = "";
    currentWordLen = 0;
  };

  for (const token of tokens) {
    if (!token.visible) {
      currentWord += token.char;
      lastAnsiState = token.char;
      continue;
    }

    if (token.char === " ") {
      flushWord();
      // Represent the space as a word of its own with visibleLen 1
      words.push({ text: " ", visibleLen: 1 });
    } else {
      currentWord += token.char;
      currentWordLen += 1;
    }
  }
  flushWord();

  // Now do word-aware line wrapping
  const lines: string[] = [];
  let currentLine = "";
  let currentVisibleLen = 0;

  for (const word of words) {
    // If adding this word would overflow and the line is non-empty, start a new line
    if (currentVisibleLen + word.visibleLen > maxWidth && currentVisibleLen > 0) {
      lines.push(currentLine + "\u001b[0m");
      currentLine = lastAnsiState;
      currentVisibleLen = 0;
    }

    currentLine += word.text;
    currentVisibleLen += word.visibleLen;
  }

  if (currentLine) {
    lines.push(currentLine);
  }

  return lines;
}

type UsageFields = {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  cachedTokens: number;
  reasoningTokens: number;
};

function extractUsageFields(usage: unknown | null): UsageFields {
  const empty: UsageFields = {
    promptTokens: 0, completionTokens: 0, totalTokens: 0,
    cachedTokens: 0, reasoningTokens: 0,
  };
  if (!usage || typeof usage !== "object" || Array.isArray(usage)) {
    return empty;
  }

  const record = usage as Record<string, unknown>;
  const promptTokens =
    typeof record.prompt_tokens === "number" ? record.prompt_tokens : 0;
  const completionTokens =
    typeof record.completion_tokens === "number"
      ? record.completion_tokens
      : 0;
  const totalTokens =
    typeof record.total_tokens === "number" ? record.total_tokens : 0;

  let cachedTokens = 0;
  const promptDetails = record.prompt_tokens_details;
  if (promptDetails && typeof promptDetails === "object" && !Array.isArray(promptDetails)) {
    const cached = (promptDetails as Record<string, unknown>).cached_tokens;
    if (typeof cached === "number") {
      cachedTokens = cached;
    }
  }

  // Some providers use prompt_cache_hit_tokens directly
  if (cachedTokens === 0 && typeof record.prompt_cache_hit_tokens === "number") {
    cachedTokens = record.prompt_cache_hit_tokens;
  }

  let reasoningTokens = 0;
  const completionDetails = record.completion_tokens_details;
  if (completionDetails && typeof completionDetails === "object" && !Array.isArray(completionDetails)) {
    const reasoning = (completionDetails as Record<string, unknown>).reasoning_tokens;
    if (typeof reasoning === "number") {
      reasoningTokens = reasoning;
    }
  }

  return { promptTokens, completionTokens, totalTokens, cachedTokens, reasoningTokens };
}

export function buildExitSummaryText(input: ExitSummaryInput): string {
  const { session, messages, model } = input;
  const stats = countToolCalls(messages);
  const timeStats = calculateTimeStats(messages);

  const sessionId = session?.id ?? "N/A";
  const successRate = stats.total > 0
    ? ((stats.succeeded / stats.total) * 100).toFixed(1)
    : "0.0";

  const createTime = session?.createTime ? new Date(session.createTime).getTime() : 0;
  const updateTime = session?.updateTime ? new Date(session.updateTime).getTime() : Date.now();
  const wallMs = createTime > 0 ? updateTime - createTime : 0;

  // Count assistant messages (API calls) for API time approximation
  const assistantCount = messages.filter((m) => m.role === "assistant").length;

  const innerWidth = 98;
  const contentWidth = innerWidth - 4; // "│  " prefix + "  │" suffix → 4 chars padding

  const borderColor = chalk.dim.gray;
  const titleColor = gradientString('#229ac3e6', 'rgb(125 51 247 / 0.7)');
  const labelColor = chalk.rgb(34, 154, 195);
  const line = (text: string) =>
    `${borderColor("|")}  ${padRight(text, contentWidth)}  ${borderColor("|")}`;

  const blank = line("");
  const header = chalk.bold(titleColor("Agent powering down. Goodbye!"));
  const divider = chalk.dim("─".repeat(contentWidth-4));

  // ── Interaction Summary section ──
  const rows: string[] = [
    "",
    `  ${header}`,
    "",
    `  ${chalk.bold("Interaction Summary")}`,
    `  ${labelColor("Session ID:")}        ${chalk.white(sessionId)}`,
    `  ${labelColor("Tool Calls:")}        ${chalk.white(String(stats.total))}  ( ${chalk.green(`✓ ${stats.succeeded}`)}  ${chalk.red(`✕ ${stats.failed}`)} )`,
    `  ${labelColor("Success Rate:")}      ${chalk.white(successRate + "%")}`,
    "",
    // `  ${chalk.bold("Performance")}`,
    // `  ${labelColor("Wall Time:")}         ${chalk.white(formatDuration(wallMs))}`,
    // `  ${labelColor("Agent Active:")}      ${chalk.white(formatDuration(wallMs))}`,
    // `    ${chalk.dim("» API Time:")}      ${chalk.white(formatDuration(timeStats.apiTimeMs))}`,
    // `    ${chalk.dim("» Tool Time:")}     ${chalk.white(formatDuration(timeStats.toolTimeMs))}`,
    // "",
  ];



  // ── Model Usage section ──
  const usage = extractUsageFields(session?.usage ?? null);
  const modelName = model ?? "unknown";
  const hasUsage = usage.promptTokens > 0 || usage.completionTokens > 0;


  // ── Context Window section ──
  rows.push(`  ${chalk.bold("Context Window")}`);

  const labelW = 24;
  const valueW = 14;

  const contextRow = (label: string, value: string) =>
    `  ${padRight(labelColor(label), labelW)}${padLeft(chalk.white(value), valueW)}`;

  rows.push(contextRow("Total Tokens:", formatNumber(usage.totalTokens)));
  rows.push(contextRow("Input Tokens:", formatNumber(usage.promptTokens)));
  rows.push(contextRow("Output Tokens:", formatNumber(usage.completionTokens)));

  if (usage.reasoningTokens > 0) {
    rows.push(contextRow("Reasoning Tokens:", formatNumber(usage.reasoningTokens)));
  }

  if (usage.cachedTokens > 0) {
    rows.push(contextRow("Cached Tokens:", formatNumber(usage.cachedTokens)));
  }

  rows.push("");

  if (hasUsage && model) {


    // Table header
    const colModel = 44;
    const colReqs = 8;
    const colInput = 18;
    const colOutput = 18;

    const headerRow =
      padRight("Model Usage", colModel) +
      padLeft("Reqs", colReqs) +
      padLeft("Input Tokens", colInput) +
      padLeft("Output Tokens", colOutput);
    rows.push(`  ${chalk.dim.black.bold(headerRow)}`);
    rows.push(`  ${divider}`);

    // Data row
    const reqsStr = String(assistantCount).padStart(colReqs);
    const inputStr = formatNumber(usage.promptTokens).padStart(colInput);
    const outputStr = formatNumber(usage.completionTokens).padStart(colOutput);
    const dataRow =
      padRight(chalk.black(modelName), colModel) +
      padRight(chalk.black(reqsStr), colReqs) +
      padRight(chalk.yellow(inputStr), colInput) +
      padRight(chalk.yellow(outputStr), colOutput);
    rows.push(`  ${dataRow}`);

    // Cache savings highlight
    if (usage.cachedTokens > 0 && usage.promptTokens > 0) {
      const cachePct = ((usage.cachedTokens / usage.promptTokens) * 100).toFixed(1);
      const savingsText =
        `${chalk.dim.rgb(34, 154, 195)("Savings Highlight:")} ${chalk.green(formatNumber(usage.cachedTokens))} ${chalk.dim(`(${cachePct}%) of input tokens were served from the cache, reducing costs.`)}`;
      const wrappedLines = wrapAnsiText(savingsText, contentWidth - 2);
      rows.push("");
      for (const wLine of wrappedLines) {
        rows.push(`  ${wLine}`);
      }
    }

    rows.push("");
    // rows.push(
    //   `  ${chalk.dim("» Tip: For a full token breakdown, run")} ${chalk.white("/stats model")}${chalk.dim(".")}`
    // );
  }

  rows.push("");

  const border = borderColor("-".repeat(innerWidth));
  const top = `${borderColor("+")}${border}${borderColor("+")}`;
  const bottom = `${borderColor("+")}${border}${borderColor("+")}`;

  const body = rows.map((row) => line(row)).join("\n");

  return [top, body, bottom].join("\n");
}
