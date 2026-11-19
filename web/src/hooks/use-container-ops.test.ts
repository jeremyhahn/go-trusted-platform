import { describe, expect, it } from 'vitest';
import { splitCommand } from './use-container-ops';

describe('splitCommand', () => {
  it('splits plain words on whitespace', () => {
    expect(splitCommand('  ls   -la /  ')).toEqual(['ls', '-la', '/']);
  });

  it('keeps a single-quoted script as one argument', () => {
    expect(splitCommand("sh -c 'echo hello'")).toEqual(['sh', '-c', 'echo hello']);
  });

  it('keeps double-quoted spaces and empty quoted arguments', () => {
    expect(splitCommand('echo "a b" ""')).toEqual(['echo', 'a b', '']);
  });

  it('honours backslash escapes outside quotes', () => {
    expect(splitCommand('echo a\\ b')).toEqual(['echo', 'a b']);
  });

  it('honours \\" and \\\\ inside double quotes', () => {
    expect(splitCommand('echo "say \\"hi\\" \\\\ ok"')).toEqual(['echo', 'say "hi" \\ ok']);
  });

  it('treats single-quoted text literally', () => {
    expect(splitCommand("echo 'a\\b \"c\"'")).toEqual(['echo', 'a\\b "c"']);
  });

  it('joins adjacent quoted and plain parts into one argument', () => {
    expect(splitCommand(`a'b c'"d"e`)).toEqual(['ab cde']);
  });

  it('returns no arguments for a blank line', () => {
    expect(splitCommand('   ')).toEqual([]);
  });

  it('throws on an unterminated quote', () => {
    expect(() => splitCommand("sh -c 'echo")).toThrow(/unterminated/i);
    expect(() => splitCommand('echo "a')).toThrow(/unterminated/i);
  });
});
