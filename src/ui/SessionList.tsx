import React, {useState, useMemo} from "react";
import {Box, Text, useInput, useWindowSize} from "ink";
import type {SessionEntry} from "../session";

type Props = {
  sessions: SessionEntry[];
  onSelect: (sessionId: string) => void;
  onCancel: () => void;
};

export function SessionList({sessions, onSelect, onCancel}: Props): React.ReactElement {
  const [index, setIndex] = useState(0);
  const {columns, rows} = useWindowSize();

  // 根据终端高度动态计算可见的会话数量
  const maxVisibleSessions = useMemo(() => {
    // 减去边框、标题、页脚、滚动指示器等占用的空间
    // 外层容器 height=rows-1，外边框2 + header1 + 内边框2 + footer1 + 滚动指示器1 = 8
    const reservedLines = 8;
    const linesPerSession = 3; // height=2 + marginBottom=1
    const availableLines = Math.max(0, rows - reservedLines);
    return Math.max(1, Math.floor(availableLines / linesPerSession));
  }, [rows]);

  // 确保index在有效范围内
  const safeIndex = useMemo(() => {
    if (sessions.length === 0) return 0;
    return Math.max(0, Math.min(index, sessions.length - 1));
  }, [index, sessions.length]);

  // 计算滚动偏移量，确保选中的项目始终可见
  const scrollOffset = useMemo(() => {
    if (safeIndex < maxVisibleSessions) return 0;
    return safeIndex - maxVisibleSessions + 1;
  }, [safeIndex, maxVisibleSessions]);

  // 获取当前可见的会话列表
  const visibleSessions = useMemo(() => {
    return sessions.slice(scrollOffset, scrollOffset + maxVisibleSessions);
  }, [sessions, scrollOffset, maxVisibleSessions]);

  useInput((input, key) => {
    if (key.escape || (key.ctrl && (input === "c" || input === "C"))) {
      onCancel();
      return;
    }
    if (sessions.length === 0) {
      return;
    }
    if (key.upArrow) {
      setIndex((i) => Math.max(0, i - 1));
      return;
    }
    if (key.downArrow) {
      setIndex((i) => Math.min(sessions.length - 1, i + 1));
      return;
    }
    if (key.pageUp) {
      setIndex((i) => Math.max(0, i - maxVisibleSessions));
      return;
    }
    if (key.pageDown) {
      setIndex((i) => Math.min(sessions.length - 1, i + maxVisibleSessions));
      return;
    }
    if (key.home) {
      setIndex(0);
      return;
    }
    if (key.end) {
      setIndex(sessions.length - 1);
      return;
    }
    if (key.return) {
      const session = sessions[safeIndex];
      if (session) {
        onSelect(session.id);
      }
    }
  });

  if (sessions.length === 0) {
    return (
      <Box flexDirection="column">
        <Text color="yellow">No previous sessions found.</Text>
        <Text dimColor>Press Esc to go back.</Text>
      </Box>
    );
  }

  return (
    <Box
      flexDirection="column"
      width={columns - 6}
      height={rows - 1}
      overflow="hidden"
      paddingX={1}
      marginTop={1}
    >
      <Box flexDirection="column" borderStyle='round' borderDimColor flexGrow={1} overflow="hidden">
        {/* Header row */}
        <Box paddingX={1}>
          <Text bold color="black">Resume a session</Text>
          <Text bold color="#229ac3"> ({sessions.length} total)</Text>
        </Box>
        {/* Session list */}
        <Box borderTop={true} borderBottom={true} borderLeft={false} borderRight={false} borderStyle='round'
             borderDimColor flexDirection='column' flexGrow={1} paddingX={1} overflow="hidden">
          {visibleSessions.map((session, i) => {
            const actualIndex = scrollOffset + i;
            return (
              <Box key={session.id} height={2} marginBottom={1}>
                <Box>
                  <Text color='#229ac3'>
                    {actualIndex === safeIndex ? "› " : "  "}
                  </Text>
                </Box>
                <Box flexDirection='column' flexGrow={1}>
                  <Box width={'100%'}>
                    <Text {...(actualIndex === safeIndex ? {bold: true} : {})} color={actualIndex === safeIndex ? "#229ac3" : undefined}>
                      {formatSessionTitle(session.summary || "Untitled")}
                    </Text>
                    <Text dimColor> ({session.status})</Text>
                  </Box>
                  <Box width='100%'>
                    <Text dimColor>{formatTimestamp(session.updateTime)} </Text>
                  </Box>
                </Box>
              </Box>
            );
          })}
          {(scrollOffset > 0 || scrollOffset + maxVisibleSessions < sessions.length) ? (
            <Box marginTop={1}>
              {scrollOffset > 0 ? <Text dimColor>… {scrollOffset} newer sessions above. </Text> : null}
              {scrollOffset + maxVisibleSessions < sessions.length ? <Text dimColor>… {sessions.length - scrollOffset - maxVisibleSessions} older sessions below.</Text> : null}
            </Box>
          ) : null}
        </Box>
        {/* Footer */}
        <Box>
          <Text dimColor>↑/↓ navigate · PgUp/PgDn page · Enter select · Esc cancel</Text>
        </Box>
      </Box>
    </Box>
  );
}

function formatTimestamp(value: string): string {
  try {
    const date = new Date(value);
    if (Number.isNaN(date.valueOf())) {
      return value;
    }
    return date.toLocaleString();
  } catch {
    return value;
  }
}

export function formatSessionTitle(value: string, max = 70): string {
  return truncate(value.replace(/\r?\n/g, " ").replace(/\s+/g, " ").trim(), max);
}

function truncate(value: string, max: number): string {
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, max)}…`;
}
