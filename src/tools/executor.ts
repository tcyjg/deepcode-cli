import type OpenAI from "openai";
import type { ReasoningEffort } from "../settings";
import { canExecuteAskUserQuestionTool, handleAskUserQuestionTool } from "./ask-user-question-handler";
import { canExecuteBashTool, handleBashTool } from "./bash-handler";
import { canExecuteEditTool, handleEditTool } from "./edit-handler";
import { canExecuteReadTool, handleReadTool } from "./read-handler";
import { canExecuteWebSearchTool, handleWebSearchTool } from "./web-search-handler";
import { canExecuteWriteTool, handleWriteTool } from "./write-handler";
import {
  buildSafetyApprovalToolResult,
  buildSafetyDeniedToolResult,
  loadProjectPermissionPolicy,
  type PermissionContext,
  type SafetyDecision,
  type SafetyApprovalRequest,
} from "./safety-hooks";

export type CreateOpenAIClient = () => {
  client: OpenAI | null;
  model: string;
  baseURL?: string;
  thinkingEnabled: boolean;
  reasoningEffort?: ReasoningEffort;
  debugLogEnabled?: boolean;
  notify?: string;
  webSearchTool?: string;
  machineId?: string;
};

export type ToolCall = {
  id: string;
  type: "function";
  function: {
    name: string;
    arguments: string;
  };
};

export type ToolExecutionContext = {
  sessionId: string;
  projectRoot: string;
  toolCall: ToolCall;
  createOpenAIClient?: CreateOpenAIClient;
  onProcessStart?: (processId: string | number, command: string) => void;
  onProcessExit?: (processId: string | number) => void;
};

export type ToolExecutionHooks = {
  onProcessStart?: (processId: string | number, command: string) => void;
  onProcessExit?: (processId: string | number) => void;
  shouldStop?: () => boolean;
  onSafetyApprovalRequested?: (request: SafetyApprovalRequest, toolCall: ToolCall) => void;
  consumeSafetyApproval?: (request: SafetyApprovalRequest) => "approved" | "denied" | "missing";
};

export type ToolExecutionResult = {
  ok: boolean;
  name: string;
  output?: string;
  error?: string;
  metadata?: Record<string, unknown>;
  awaitUserResponse?: boolean;
  followUpMessages?: ToolExecutionFollowUpMessage[];
};

export type ToolExecutionFollowUpMessage = {
  role: "system";
  content: string;
  contentParams?: unknown | null;
};

export type ToolHandler = (
  args: Record<string, unknown>,
  context: ToolExecutionContext
) => Promise<ToolExecutionResult>;

export type ToolPermissionCheck = (args: Record<string, unknown>, context: PermissionContext) => SafetyDecision;

type ToolDefinition = {
  handler: ToolHandler;
  canExecute: ToolPermissionCheck;
};

export type ToolCallExecution = {
  toolCallId: string;
  content: string;
  result: ToolExecutionResult;
};

export class ToolExecutor {
  private readonly projectRoot: string;
  private readonly createOpenAIClient?: CreateOpenAIClient;
  private readonly tools = new Map<string, ToolDefinition>();

  constructor(projectRoot: string, createOpenAIClient?: CreateOpenAIClient) {
    this.projectRoot = projectRoot;
    this.createOpenAIClient = createOpenAIClient;
    this.registerToolHandlers();
  }

  async executeToolCalls(
    sessionId: string,
    toolCalls: unknown[],
    hooks?: ToolExecutionHooks
  ): Promise<ToolCallExecution[]> {
    const parsedCalls = toolCalls
      .map((toolCall) => this.parseToolCall(toolCall))
      .filter((toolCall): toolCall is ToolCall => Boolean(toolCall));

    const executions: ToolCallExecution[] = [];
    for (const toolCall of parsedCalls) {
      if (hooks?.shouldStop?.()) {
        break;
      }
      const result = await this.executeToolCall(sessionId, toolCall, hooks);
      executions.push({
        toolCallId: toolCall.id,
        content: this.formatToolResult(result),
        result,
      });
      if (hooks?.shouldStop?.()) {
        break;
      }
    }
    return executions;
  }

  private registerToolHandlers(): void {
    this.tools.set("bash", { handler: handleBashTool, canExecute: canExecuteBashTool });
    this.tools.set("read", { handler: handleReadTool, canExecute: canExecuteReadTool });
    this.tools.set("write", { handler: handleWriteTool, canExecute: canExecuteWriteTool });
    this.tools.set("edit", { handler: handleEditTool, canExecute: canExecuteEditTool });
    this.tools.set("AskUserQuestion", {
      handler: handleAskUserQuestionTool,
      canExecute: canExecuteAskUserQuestionTool,
    });
    this.tools.set("WebSearch", { handler: handleWebSearchTool, canExecute: canExecuteWebSearchTool });
  }

  private parseToolCall(toolCall: unknown): ToolCall | null {
    if (!toolCall || typeof toolCall !== "object") {
      return null;
    }

    const record = toolCall as {
      id?: unknown;
      type?: unknown;
      function?: { name?: unknown; arguments?: unknown };
    };

    if (typeof record.id !== "string") {
      return null;
    }

    const functionRecord = record.function;
    if (!functionRecord || typeof functionRecord !== "object") {
      return null;
    }

    if (typeof functionRecord.name !== "string") {
      return null;
    }

    const rawArguments = typeof functionRecord.arguments === "string" ? functionRecord.arguments : "";

    return {
      id: record.id,
      type: "function",
      function: {
        name: functionRecord.name,
        arguments: rawArguments,
      },
    };
  }

  private async executeToolCall(
    sessionId: string,
    toolCall: ToolCall,
    hooks?: ToolExecutionHooks
  ): Promise<ToolExecutionResult> {
    const toolName = toolCall.function.name;
    const tool = this.tools.get(toolName);
    if (!tool) {
      return {
        ok: false,
        name: toolName,
        error: `Unknown tool: ${toolName}`,
      };
    }

    const parsedArgs = this.parseToolArguments(toolCall.function.arguments);
    if (!parsedArgs.ok) {
      return {
        ok: false,
        name: toolName,
        error: parsedArgs.error,
      };
    }

    const safetyDecision = tool.canExecute(parsedArgs.args, this.buildPermissionContext());
    if (safetyDecision.action === "block") {
      return {
        ok: false,
        name: toolName,
        error: `Blocked by safety hook: ${safetyDecision.reason}`,
        metadata: {
          safety_hook: {
            action: "blocked",
            reason: safetyDecision.reason,
          },
        },
      };
    }

    if (safetyDecision.action === "confirm") {
      const approvalState = hooks?.consumeSafetyApproval?.(safetyDecision.request) ?? "missing";
      if (approvalState === "denied") {
        return buildSafetyDeniedToolResult(safetyDecision.request);
      }
      if (approvalState !== "approved") {
        hooks?.onSafetyApprovalRequested?.(safetyDecision.request, toolCall);
        return buildSafetyApprovalToolResult(safetyDecision.request);
      }
    }

    try {
      return await tool.handler(parsedArgs.args, {
        sessionId,
        projectRoot: this.projectRoot,
        toolCall,
        createOpenAIClient: this.createOpenAIClient,
        onProcessStart: hooks?.onProcessStart,
        onProcessExit: hooks?.onProcessExit,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        ok: false,
        name: toolName,
        error: message,
      };
    }
  }

  private buildPermissionContext(): PermissionContext {
    return {
      projectRoot: this.projectRoot,
      policy: loadProjectPermissionPolicy(this.projectRoot),
    };
  }

  private parseToolArguments(
    rawArguments: string
  ): { ok: true; args: Record<string, unknown> } | { ok: false; error: string } {
    if (!rawArguments) {
      return { ok: true, args: {} };
    }

    try {
      const parsed = JSON.parse(rawArguments);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { ok: false, error: "InputParseError: Tool arguments must be a JSON object." };
      }
      return { ok: true, args: parsed as Record<string, unknown> };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        ok: false,
        error:
          `InputParseError: Failed to parse tool arguments: ${message}. ` +
          "Ensure the tool call arguments are valid JSON. Prefer Edit over Write for large existing-file changes.",
      };
    }
  }

  private formatToolResult(result: ToolExecutionResult): string {
    const payload: Record<string, unknown> = {
      ok: result.ok,
      name: result.name,
    };

    if (typeof result.output !== "undefined") {
      payload.output = result.output;
    }

    if (result.error) {
      payload.error = result.error;
    }

    if (result.metadata && Object.keys(result.metadata).length > 0) {
      payload.metadata = result.metadata;
    }

    if (result.awaitUserResponse === true) {
      payload.awaitUserResponse = true;
    }

    return JSON.stringify(payload, null, 2);
  }
}
