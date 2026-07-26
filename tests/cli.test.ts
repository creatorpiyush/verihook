import { describe, expect, it, vi } from 'vitest';
import { runCli } from '../src/cli/index.js';

describe('verihook CLI Simulator', () => {
  it('should print help menu when no provider is passed', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runCli([]);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('npx verihook simulate'));
    consoleSpy.mockRestore();
  });

  it('should generate valid cURL command with --curl flag', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runCli(['simulate', 'stripe', '--curl']);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('curl -X POST'));
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('stripe-signature'));
    consoleSpy.mockRestore();
  });
});
