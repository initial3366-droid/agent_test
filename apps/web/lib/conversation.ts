export type ConversationTurn = { user: string; assistant: string };

export function buildContextPrompt(history: ConversationTurn[], current: string): string {
  const recent = history.slice(-12);
  if (!recent.length) return current;
  const transcript = recent.map((turn, index) =>
    `Turn ${index + 1}\nUser: ${turn.user}\nAssistant: ${turn.assistant}`
  ).join("\n\n");
  const header = "Continue the existing conversation. Resolve short replies such as yes/no using the prior turn.\n\n";
  const currentBlock = `\n\nCurrent user message:\n${current}`;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();
  const budget = 96_000;
  const fixed = encoder.encode(header + currentBlock);
  if (fixed.length >= budget) return decoder.decode(fixed.slice(0, budget));
  const historyBytes = encoder.encode(transcript);
  const available = budget - fixed.length;
  const clippedHistory = historyBytes.length > available
    ? decoder.decode(historyBytes.slice(historyBytes.length - available))
    : transcript;
  return `${header}${clippedHistory}${currentBlock}`;
}

export function modelChoices(content: string): string[] {
  const asksQuestion = /[?？]|是否|要不要|请选择|请确认|哪个方案|哪种方案/.test(content);
  if (!asksQuestion) return [];
  const listed = content.split(/\r?\n/).map(line => {
    const match = line.match(/^\s*(?:\d+[.)、]|[-*])\s*(.+?)\s*$/);
    return match?.[1]?.slice(0, 160) ?? "";
  }).filter(Boolean).slice(0, 6);
  return listed.length >= 2 ? listed : ["确认，继续执行", "取消，不要执行"];
}
