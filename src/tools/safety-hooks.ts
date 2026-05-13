import * as fs from "fs";
import * as path from "path";

export type PermissionPolicy = {
  rules?: PermissionRule[];
  tools?: Record<string, SafetyAction>;
  bash?: {
    defaultAction?: SafetyAction;
    allowCommands?: string[];
    confirmCommands?: string[];
    restrictCommands?: string[];
    blockCommands?: string[];
  };
  filesystem?: {
    outsideProject?: SafetyAction;
    emptyExistingFile?: SafetyAction;
    contentRemoval?: SafetyAction;
  };
};

export type PermissionRule = {
  tool: string;
  action: SafetyAction;
  match?: {
    command?: string;
    filePath?: string;
  };
  reason?: string;
  scope?: "exact" | "project";
};

export type PermissionContext = {
  projectRoot: string;
  policy: PermissionPolicy;
};

export type SafetyApprovalRequest = {
  id: string;
  toolName: string;
  reason: string;
  command?: string;
  filePath?: string;
  question: string;
};

export type SafetyAction = "ALLOW" | "CONFIRM" | "RESTRICT" | "DENY";

export type SafetyDecision =
  | { action: "allow" }
  | { action: "block"; reason: string }
  | { action: "confirm"; request: SafetyApprovalRequest };

const ALLOW_LABEL = "Allow once";
const ALWAYS_ALLOW_LABEL = "Always allow in this project";
const DENY_LABEL = "Deny";

const DEFAULT_PERMISSION_POLICY: PermissionPolicy = {
  tools: {
    read: "ALLOW",
    WebSearch: "ALLOW",
    AskUserQuestion: "ALLOW",
  },
  bash: {
    defaultAction: "ALLOW",
  },
  filesystem: {
    outsideProject: "CONFIRM",
    emptyExistingFile: "CONFIRM",
    contentRemoval: "CONFIRM",
  },
  rules: [
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "rm" },
      reason: "The command appears to delete files or directories.",
    },
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "del" },
      reason: "The command appears to delete files or directories.",
    },
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "erase" },
      reason: "The command appears to delete files or directories.",
    },
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "rmdir" },
      reason: "The command appears to delete files or directories.",
    },
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "rd" },
      reason: "The command appears to delete files or directories.",
    },
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "unlink" },
      reason: "The command appears to delete files or directories.",
    },
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "Remove-Item" },
      reason: "The command appears to delete files or directories.",
    },
    {
      tool: "bash",
      action: "ALLOW",
      scope: "project",
      match: { command: "git rm" },
      reason: "git rm deletes files from the working tree.",
    },
  ],
};

export function loadProjectPermissionPolicy(projectRoot: string): PermissionPolicy {
  const filePolicy = readPolicyFile(path.join(projectRoot, ".deepcode", "permissions.json"));
  const settingsPolicy = readPolicyFromSettings(path.join(projectRoot, ".deepcode", "settings.json"));
  return mergePermissionPolicies(DEFAULT_PERMISSION_POLICY, filePolicy, settingsPolicy);
}

export function recordProjectAllowedApproval(projectRoot: string, request: SafetyApprovalRequest): void {
  const permissionsPath = path.join(projectRoot, ".deepcode", "permissions.json");
  const current = readPolicyFile(permissionsPath);
  const rules = Array.isArray(current.rules) ? current.rules.slice() : [];
  const rule = buildAllowRuleFromApproval(projectRoot, request);
  if (!rules.some((item) => permissionRuleMatchesRequest(item, request, projectRoot))) {
    rules.push(rule);
  }

  const nextPolicy: PermissionPolicy = {
    ...pickWritablePolicyFields(current),
    rules,
  };

  fs.mkdirSync(path.dirname(permissionsPath), { recursive: true });
  fs.writeFileSync(permissionsPath, `${JSON.stringify(nextPolicy, null, 2)}\n`, "utf8");
}

export function evaluateGenericToolSafety(
  toolName: string,
  _args: Record<string, unknown>,
  context: PermissionContext
): SafetyDecision {
  const configuredAction = normalizeSafetyAction(context.policy.tools?.[toolName]);
  if (configuredAction) {
    return actionToDecisionWithAllowlist(context, configuredAction, {
      toolName,
      reason: `Project policy marks ${toolName} as ${configuredAction}.`,
    });
  }

  if (isReadOnlyTool(toolName)) {
    return { action: "allow" };
  }

  return actionToDecisionWithAllowlist(context, "CONFIRM", {
    toolName,
    reason: `No explicit permission policy exists for ${toolName}.`,
  });
}

export function evaluateReadToolSafety(args: Record<string, unknown>, context: PermissionContext): SafetyDecision {
  const filePath = typeof args.file_path === "string" ? normalizePath(args.file_path) : undefined;

  const ruleDecision = findMatchingRuleDecision(context, {
    toolName: "read",
    filePath,
  });
  if (ruleDecision) {
    return ruleDecision;
  }

  if (filePath && isOutsideProject(filePath, context.projectRoot)) {
    return actionToDecisionWithAllowlist(
      context,
      normalizeSafetyAction(context.policy.filesystem?.outsideProject) ?? "CONFIRM",
      {
        toolName: "read",
        reason: "The read targets a file outside the current project.",
        filePath,
      }
    );
  }

  return { action: "allow" };
}

export function evaluateBashToolSafety(args: Record<string, unknown>, context: PermissionContext): SafetyDecision {
  const command = typeof args.command === "string" ? args.command.trim() : "";
  if (!command) {
    return { action: "allow" };
  }

  const ruleDecision = findMatchingRuleDecision(context, {
    toolName: "bash",
    command,
  });
  if (ruleDecision) {
    return ruleDecision;
  }

  const configuredAction = matchConfiguredCommandAction(command, context.policy.bash);
  if (configuredAction) {
    return actionToDecisionWithAllowlist(context, configuredAction, {
      toolName: "bash",
      reason: `Project bash policy marks this command as ${configuredAction}.`,
      command,
    });
  }

  const normalized = normalizeCommand(command);
  const outsideProjectReference = findOutsideProjectReference(normalized, context.projectRoot);
  if (outsideProjectReference) {
    return confirmUnlessAllowed(context, {
      toolName: "bash",
      reason: `The command references a path outside the current project: ${outsideProjectReference}`,
      command,
    });
  }

  const catastrophicReason = detectCatastrophicCommand(normalized);
  if (catastrophicReason) {
    return {
      action: "block",
      reason: catastrophicReason,
    };
  }

  const destructiveReason = detectDestructiveCommand(normalized);
  if (destructiveReason) {
    return confirmUnlessAllowed(context, {
      toolName: "bash",
      reason: destructiveReason,
      command,
    });
  }

  if (isReadOnlyCommand(normalized)) {
    return { action: "allow" };
  }

  const defaultAction = normalizeSafetyAction(context.policy.bash?.defaultAction) ?? "CONFIRM";
  return actionToDecisionWithAllowlist(context, defaultAction, {
    toolName: "bash",
    reason: "Shell commands are not on the read-only allowlist.",
    command,
  });
}

export function evaluateEditToolSafety(args: Record<string, unknown>, context: PermissionContext): SafetyDecision {
  const oldString = typeof args.old_string === "string" ? args.old_string : "";
  const newString = typeof args.new_string === "string" ? args.new_string : "";
  const filePath = typeof args.file_path === "string" ? normalizePath(args.file_path) : undefined;

  const ruleDecision = findMatchingRuleDecision(context, {
    toolName: "edit",
    filePath,
  });
  if (ruleDecision) {
    return ruleDecision;
  }

  if (oldString.trim().length > 0 && newString.trim().length === 0) {
    return actionToDecisionWithAllowlist(
      context,
      normalizeSafetyAction(context.policy.filesystem?.contentRemoval) ?? "CONFIRM",
      {
        toolName: "edit",
        reason: "The edit removes content by replacing text with an empty string.",
        filePath,
      }
    );
  }

  if (filePath && isOutsideProject(filePath, context.projectRoot)) {
    return actionToDecisionWithAllowlist(
      context,
      normalizeSafetyAction(context.policy.filesystem?.outsideProject) ?? "CONFIRM",
      {
        toolName: "edit",
        reason: "The edit targets a file outside the current project.",
        filePath,
      }
    );
  }

  return { action: "allow" };
}

export function evaluateWriteToolSafety(args: Record<string, unknown>, context: PermissionContext): SafetyDecision {
  const filePath = typeof args.file_path === "string" ? normalizePath(args.file_path) : undefined;
  const content = typeof args.content === "string" ? args.content : "";

  const ruleDecision = findMatchingRuleDecision(context, {
    toolName: "write",
    filePath,
  });
  if (ruleDecision) {
    return ruleDecision;
  }

  if (filePath && fs.existsSync(filePath) && content.trim().length === 0) {
    return actionToDecisionWithAllowlist(
      context,
      normalizeSafetyAction(context.policy.filesystem?.emptyExistingFile) ?? "CONFIRM",
      {
        toolName: "write",
        reason: "The write would empty an existing file.",
        filePath,
      }
    );
  }

  if (filePath && isOutsideProject(filePath, context.projectRoot)) {
    return actionToDecisionWithAllowlist(
      context,
      normalizeSafetyAction(context.policy.filesystem?.outsideProject) ?? "CONFIRM",
      {
        toolName: "write",
        reason: "The write targets a file outside the current project.",
        filePath,
      }
    );
  }

  return { action: "allow" };
}

export function describeSafetyAction(action: SafetyAction): string {
  if (action === "ALLOW") {
    return "ALLOW: run directly";
  }
  if (action === "CONFIRM") {
    return "CONFIRM: require user approval before running";
  }
  if (action === "RESTRICT") {
    return "RESTRICT: run only after validating command arguments and paths";
  }
  return "DENY: block without asking the user";
}

export function buildSafetyApprovalToolResult(request: SafetyApprovalRequest): {
  ok: boolean;
  name: string;
  output: string;
  metadata: Record<string, unknown>;
  awaitUserResponse: true;
} {
  return {
    ok: true,
    name: "SafetyApproval",
    output: [
      "Waiting for user approval before running a potentially destructive operation.",
      "",
      `Tool: ${request.toolName}`,
      `Reason: ${request.reason}`,
      request.command ? `Command: ${request.command}` : null,
      request.filePath ? `File: ${request.filePath}` : null,
    ]
      .filter((line): line is string => line !== null)
      .join("\n"),
    metadata: {
      kind: "ask_user_question",
      safety_hook: {
        id: request.id,
        tool_name: request.toolName,
        reason: request.reason,
        command: request.command,
        file_path: request.filePath,
      },
      questions: [
        {
          question: request.question,
          options: [
            {
              label: ALLOW_LABEL,
              description: "Run this operation one time.",
            },
            {
              label: ALWAYS_ALLOW_LABEL,
              description: "Run this exact operation now and allow it automatically in this project later.",
            },
            {
              label: DENY_LABEL,
              description: "Do not run this operation.",
            },
          ],
        },
      ],
    },
    awaitUserResponse: true,
  };
}

export function buildSafetyDeniedToolResult(request: SafetyApprovalRequest): {
  ok: false;
  name: string;
  error: string;
  metadata: Record<string, unknown>;
} {
  return {
    ok: false,
    name: request.toolName,
    error: `User denied approval for this operation: ${request.reason}`,
    metadata: {
      safety_hook: {
        id: request.id,
        reason: request.reason,
      },
    },
  };
}

export function getSafetyApprovalLabels(): { allow: string; alwaysAllow: string; deny: string } {
  return { allow: ALLOW_LABEL, alwaysAllow: ALWAYS_ALLOW_LABEL, deny: DENY_LABEL };
}

function isReadOnlyTool(toolName: string): boolean {
  return toolName === "read" || toolName === "WebSearch" || toolName === "AskUserQuestion";
}

function detectCatastrophicCommand(command: string): string | null {
  const compact = command.replace(/\s+/g, " ");
  if (/\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)\s+(?:--\s+)?\/(?:\s|$)/i.test(compact)) {
    return "Refusing to recursively delete the filesystem root.";
  }

  if (
    /\bremove-item\b[^;&|]*\b(?:-recurse\b[^;&|]*\b-force|-force\b[^;&|]*\b-recurse)\b[^;&|]*(?:[a-z]:\\|\/)(?:\s|$)/i.test(
      compact
    )
  ) {
    return "Refusing to recursively delete a drive or filesystem root.";
  }

  if (/\bformat(?:\.com)?\b/i.test(compact) || /\bdiskpart\b/i.test(compact)) {
    return "Refusing to run disk formatting or partitioning commands.";
  }

  return null;
}

function detectDestructiveCommand(command: string): string | null {
  if (/\b(?:rm|unlink|del|erase|rmdir|rd)\b/i.test(command)) {
    return "The command appears to delete files or directories.";
  }

  if (/\bremove-item\b/i.test(command)) {
    return "The command appears to delete files or directories.";
  }

  if (/\bgit\s+clean\b/i.test(command)) {
    return "git clean can permanently remove untracked files.";
  }

  if (/\bgit\s+reset\b[^;&|]*\s--hard\b/i.test(command)) {
    return "git reset --hard can discard local changes.";
  }

  if (/\bgit\s+(?:checkout|restore)\b[^;&|]*\s--\s+/i.test(command)) {
    return "The git command can discard local file changes.";
  }

  if (/\bgit\s+rm\b/i.test(command)) {
    return "git rm deletes files from the working tree.";
  }

  if (/\bpython(?:3|\.exe)?\b[\s\S]*\b(?:os\.(?:remove|unlink|rmdir)|shutil\.rmtree)\b/i.test(command)) {
    return "The Python command appears to delete files or directories.";
  }

  if (/\bnode(?:\.exe)?\b[\s\S]*\bfs\.(?:rmSync|unlinkSync|rmdirSync|rm|unlink|rmdir)\b/i.test(command)) {
    return "The Node.js command appears to delete files or directories.";
  }

  return null;
}

function isReadOnlyCommand(command: string): boolean {
  return (
    /^(?:pwd|ls|dir|echo|printf|cat|head|tail|rg|grep|find\s+[^;&|]*|-?git\s+(?:status|diff|log|show|branch))(?:\s|$)/i.test(
      command
    ) &&
    !/[;&|`$<>]/.test(command) &&
    !/\b(?:rm|del|erase|rmdir|rd|unlink|remove-item|mv|move|cp|copy|chmod|chown|curl|wget|npm\s+install|pip\s+install)\b/i.test(
      command
    )
  );
}

function actionToDecision(
  action: SafetyAction,
  input: {
    toolName: string;
    reason: string;
    command?: string;
    filePath?: string;
  }
): SafetyDecision {
  if (action === "ALLOW") {
    return { action: "allow" };
  }
  if (action === "DENY") {
    return { action: "block", reason: input.reason };
  }
  if (action === "RESTRICT") {
    return { action: "block", reason: `Restricted operation lacks enough context to run safely: ${input.reason}` };
  }
  return {
    action: "confirm",
    request: buildApprovalRequest(input),
  };
}

function actionToDecisionWithAllowlist(
  context: PermissionContext,
  action: SafetyAction,
  input: {
    toolName: string;
    reason: string;
    command?: string;
    filePath?: string;
  }
): SafetyDecision {
  if (action === "RESTRICT") {
    return restrictedDecision(context, input);
  }
  if (action !== "CONFIRM") {
    return actionToDecision(action, input);
  }
  return confirmUnlessAllowed(context, input);
}

function restrictedDecision(
  context: PermissionContext,
  input: {
    toolName: string;
    reason: string;
    command?: string;
    filePath?: string;
  }
): SafetyDecision {
  if (input.toolName === "bash" && input.command) {
    const restrictionResult = validateRestrictedBashCommand(input.command, context.projectRoot);
    if (restrictionResult.type === "block") {
      return {
        action: "block",
        reason: restrictionResult.reason,
      };
    }
    if (restrictionResult.type === "confirm") {
      return confirmUnlessAllowed(context, {
        toolName: input.toolName,
        reason: restrictionResult.reason,
        command: input.command,
      });
    }
    return { action: "allow" };
  }

  if (input.filePath && isOutsideProject(normalizePath(input.filePath), context.projectRoot)) {
    return confirmUnlessAllowed(context, {
      toolName: input.toolName,
      reason: "Restricted file operation targets a path outside the current project.",
      filePath: input.filePath,
    });
  }

  return { action: "allow" };
}

function validateRestrictedBashCommand(
  command: string,
  projectRoot: string
): { type: "allow" } | { type: "confirm"; reason: string } | { type: "block"; reason: string } {
  const normalized = normalizeCommand(command);
  if (/[;&|`$<>]/.test(normalized) || /\n/.test(normalized)) {
    return {
      type: "block",
      reason:
        "Restricted bash commands cannot use shell control operators, expansion, redirection, or multiple commands.",
    };
  }

  const catastrophicReason = detectCatastrophicCommand(normalized);
  if (catastrophicReason) {
    return { type: "block", reason: catastrophicReason };
  }

  const destructiveReason = detectDestructiveCommand(normalized);
  if (destructiveReason) {
    return {
      type: "block",
      reason: `Restricted bash command is destructive: ${destructiveReason}`,
    };
  }

  for (const candidatePath of extractAbsolutePaths(normalized)) {
    if (isOutsideProject(candidatePath, projectRoot)) {
      return {
        type: "confirm",
        reason: `Restricted bash command references a path outside the current project: ${candidatePath}`,
      };
    }
  }

  return { type: "allow" };
}

function extractAbsolutePaths(command: string): string[] {
  const paths = new Set<string>();
  const quotedPattern = /"([^"]+)"|'([^']+)'/g;
  for (const match of command.matchAll(quotedPattern)) {
    const value = match[1] ?? match[2] ?? "";
    if (isAbsoluteLikePath(value)) {
      paths.add(normalizePath(value));
    }
  }

  for (const token of command.split(/\s+/)) {
    const cleaned = token.replace(/^["']|["']$/g, "");
    if (isAbsoluteLikePath(cleaned)) {
      paths.add(normalizePath(cleaned));
    }
  }

  return Array.from(paths);
}

function isAbsoluteLikePath(value: string): boolean {
  return path.isAbsolute(value) || /^[a-z]:[\\/]/i.test(value);
}

function confirmUnlessAllowed(
  context: PermissionContext,
  input: {
    toolName: string;
    reason: string;
    command?: string;
    filePath?: string;
  }
): SafetyDecision {
  const request = buildApprovalRequest(input);
  if (isApprovalAllowedByProjectPolicy(context.policy, request, context.projectRoot)) {
    return { action: "allow" };
  }
  return {
    action: "confirm",
    request,
  };
}

function findMatchingRuleDecision(
  context: PermissionContext,
  input: {
    toolName: string;
    command?: string;
    filePath?: string;
  }
): SafetyDecision | null {
  const rules = Array.isArray(context.policy.rules) ? context.policy.rules : [];
  for (const rule of rules) {
    if (!permissionRuleMatchesInput(rule, input, context.projectRoot)) {
      continue;
    }
    const action = normalizeSafetyAction(rule.action) ?? "CONFIRM";
    return actionToDecisionWithAllowlist(context, action, {
      toolName: input.toolName,
      reason: rule.reason || `Project rule marks ${input.toolName} as ${action}.`,
      command: input.command,
      filePath: input.filePath,
    });
  }
  return null;
}

function isApprovalAllowedByProjectPolicy(
  policy: PermissionPolicy,
  request: SafetyApprovalRequest,
  projectRoot: string
): boolean {
  return (policy.rules ?? []).some(
    (rule) => normalizeSafetyAction(rule.action) === "ALLOW" && permissionRuleMatchesRequest(rule, request, projectRoot)
  );
}

function buildAllowRuleFromApproval(projectRoot: string, request: SafetyApprovalRequest): PermissionRule {
  const projectScopedRule = buildProjectScopedAllowRule(projectRoot, request);
  if (projectScopedRule) {
    return projectScopedRule;
  }

  return {
    tool: request.toolName,
    action: "ALLOW",
    match: {
      command: request.command,
      filePath: request.filePath,
    },
    reason: request.reason,
    scope: "exact",
  };
}

function buildProjectScopedAllowRule(projectRoot: string, request: SafetyApprovalRequest): PermissionRule | null {
  if (request.toolName !== "bash" || !request.command) {
    return null;
  }

  const normalized = normalizeCommand(request.command);
  if (!detectDestructiveCommand(normalized)) {
    return null;
  }

  const commandKey = extractCommandKey(normalized);
  if (!commandKey) {
    return null;
  }

  const paths = extractAbsolutePaths(normalized);
  if (paths.length === 0 || paths.some((candidatePath) => isOutsideProject(candidatePath, projectRoot))) {
    return null;
  }

  return {
    tool: request.toolName,
    action: "ALLOW",
    match: {
      command: commandKey,
    },
    reason: request.reason,
    scope: "project",
  };
}

function permissionRuleMatchesRequest(
  rule: PermissionRule,
  request: SafetyApprovalRequest,
  projectRoot: string
): boolean {
  return permissionRuleMatchesInput(
    rule,
    {
      toolName: request.toolName,
      command: request.command,
      filePath: request.filePath,
    },
    projectRoot
  );
}

function permissionRuleMatchesInput(
  rule: PermissionRule,
  input: {
    toolName: string;
    command?: string;
    filePath?: string;
  },
  projectRoot: string
): boolean {
  if (!rule || rule.tool !== input.toolName) {
    return false;
  }

  const scope = rule.scope ?? "exact";
  const match = rule.match ?? {};
  if (scope === "project") {
    return permissionRuleMatchesProjectScope(rule, input, projectRoot);
  }

  if (match.command && match.command !== input.command) {
    return false;
  }
  if (match.filePath && normalizePath(match.filePath) !== (input.filePath ? normalizePath(input.filePath) : "")) {
    return false;
  }
  return Boolean(match.command || match.filePath);
}

function permissionRuleMatchesProjectScope(
  rule: PermissionRule,
  input: {
    toolName: string;
    command?: string;
    filePath?: string;
  },
  projectRoot: string
): boolean {
  const match = rule.match ?? {};

  if (input.toolName === "bash") {
    if (!input.command || !match.command) {
      return false;
    }
    const commandKey = extractCommandKey(normalizeCommand(input.command));
    if (commandKey !== match.command) {
      return false;
    }
    const paths = extractAbsolutePaths(input.command);
    if (paths.length > 0) {
      return paths.every((candidatePath) => !isOutsideProject(candidatePath, projectRoot));
    }
    return !referencesParentDirectory(input.command);
  }

  if (!input.filePath) {
    return false;
  }
  return !isOutsideProject(normalizePath(input.filePath), projectRoot);
}

function buildApprovalRequest(input: {
  toolName: string;
  reason: string;
  command?: string;
  filePath?: string;
}): SafetyApprovalRequest {
  const target = input.command ?? input.filePath ?? input.toolName;
  return {
    id: crypto.randomUUID(),
    toolName: input.toolName,
    reason: input.reason,
    command: input.command,
    filePath: input.filePath,
    question: `Approve this ${input.toolName} operation? ${input.reason} Target: ${target}`,
  };
}

function matchConfiguredCommandAction(
  command: string,
  policy: PermissionPolicy["bash"] | undefined
): SafetyAction | null {
  if (!policy) {
    return null;
  }
  for (const action of ["DENY", "CONFIRM", "RESTRICT", "ALLOW"] as const) {
    const patterns =
      action === "DENY"
        ? policy.blockCommands
        : action === "CONFIRM"
          ? policy.confirmCommands
          : action === "RESTRICT"
            ? policy.restrictCommands
            : policy.allowCommands;
    if (matchesAnyPattern(command, patterns)) {
      return action;
    }
  }
  return null;
}

function matchesAnyPattern(value: string, patterns: string[] | undefined): boolean {
  if (!Array.isArray(patterns)) {
    return false;
  }
  return patterns.some((pattern) => matchesPattern(value, pattern));
}

function matchesPattern(value: string, pattern: string): boolean {
  if (!pattern) {
    return false;
  }
  if (pattern.startsWith("/") && pattern.endsWith("/") && pattern.length > 2) {
    try {
      return new RegExp(pattern.slice(1, -1), "i").test(value);
    } catch {
      return false;
    }
  }
  return value.toLowerCase().includes(pattern.toLowerCase());
}

function normalizeCommand(command: string): string {
  return command.replace(/`/g, "").trim();
}

function extractCommandKey(command: string): string | null {
  if (!command) {
    return null;
  }
  const normalized = command.trim();
  const gitRmMatch = normalized.match(/^git\s+rm\b/i);
  if (gitRmMatch) {
    return "git rm";
  }
  const removeItemMatch = normalized.match(/^remove-item\b/i);
  if (removeItemMatch) {
    return "Remove-Item";
  }
  const firstToken = normalized.split(/\s+/, 1)[0];
  return firstToken || null;
}

function normalizePath(filePath: string): string {
  return path.resolve(filePath);
}

function isOutsideProject(filePath: string, projectRoot: string): boolean {
  const relative = path.relative(path.resolve(projectRoot), filePath);
  return Boolean(relative) && (relative.startsWith("..") || path.isAbsolute(relative));
}

function readPolicyFile(filePath: string): PermissionPolicy {
  try {
    if (!fs.existsSync(filePath)) {
      return {};
    }
    return normalizePermissionPolicy(JSON.parse(fs.readFileSync(filePath, "utf8")));
  } catch {
    return {};
  }
}

function readPolicyFromSettings(filePath: string): PermissionPolicy {
  try {
    if (!fs.existsSync(filePath)) {
      return {};
    }
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8")) as { permissions?: unknown };
    return normalizePermissionPolicy(parsed.permissions);
  } catch {
    return {};
  }
}

function normalizePermissionPolicy(value: unknown): PermissionPolicy {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value as PermissionPolicy;
}

function mergePermissionPolicies(...policies: PermissionPolicy[]): PermissionPolicy {
  const merged: PermissionPolicy = {};

  for (const policy of policies) {
    if (!policy || typeof policy !== "object") {
      continue;
    }

    if (policy.tools) {
      merged.tools = {
        ...(merged.tools ?? {}),
        ...policy.tools,
      };
    }

    if (policy.bash) {
      merged.bash = {
        ...(merged.bash ?? {}),
        ...policy.bash,
        allowCommands: mergeStringLists(merged.bash?.allowCommands, policy.bash.allowCommands),
        confirmCommands: mergeStringLists(merged.bash?.confirmCommands, policy.bash.confirmCommands),
        restrictCommands: mergeStringLists(merged.bash?.restrictCommands, policy.bash.restrictCommands),
        blockCommands: mergeStringLists(merged.bash?.blockCommands, policy.bash.blockCommands),
      };
    }

    if (policy.filesystem) {
      merged.filesystem = {
        ...(merged.filesystem ?? {}),
        ...policy.filesystem,
      };
    }

    if (policy.rules) {
      merged.rules = [...(merged.rules ?? []), ...policy.rules];
    }
  }

  return merged;
}

function mergeStringLists(existing: string[] | undefined, next: string[] | undefined): string[] | undefined {
  if (!existing?.length && !next?.length) {
    return undefined;
  }
  return [...(existing ?? []), ...(next ?? [])];
}

function pickWritablePolicyFields(policy: PermissionPolicy): PermissionPolicy {
  return {
    ...(policy.tools ? { tools: policy.tools } : {}),
    ...(policy.bash ? { bash: policy.bash } : {}),
    ...(policy.filesystem ? { filesystem: policy.filesystem } : {}),
    ...(policy.rules ? { rules: policy.rules } : {}),
  };
}

function normalizeSafetyAction(value: unknown): SafetyAction | null {
  return value === "ALLOW" || value === "CONFIRM" || value === "RESTRICT" || value === "DENY" ? value : null;
}

function findOutsideProjectReference(command: string, projectRoot: string): string | null {
  for (const candidatePath of extractAbsolutePaths(command)) {
    if (isOutsideProject(candidatePath, projectRoot)) {
      return candidatePath;
    }
  }

  if (referencesParentDirectory(command)) {
    return "..";
  }

  return null;
}

function referencesParentDirectory(command: string): boolean {
  return /(^|[\s"'=])\.\.(?:[\\/]|$)/.test(command);
}
