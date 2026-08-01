import { describe, expect, it, vi } from 'vitest';
import { runCli } from '../src/cli/index.js';

describe('verihook CLI Simulator', () => {
  it('should print help menu when no provider is passed', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runCli([]);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('npx verihook simulate'));
    consoleSpy.mockRestore();
  });

  it('should generate valid cURL command with --curl flag for Stripe', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runCli(['simulate', 'stripe', '--curl']);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('curl -X POST'));
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('stripe-signature'));
    consoleSpy.mockRestore();
  });

  it('should handle Twilio simulation with query parameters on target URL', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runCli(['simulate', 'twilio', '--url', 'http://localhost:3000/webhook?env=dev', '--curl']);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('http://localhost:3000/webhook?env=dev'));
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('x-twilio-signature'));
    consoleSpy.mockRestore();
  });

  it('should generate cURL for GitHub simulation with custom event', async () => {
    const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    await runCli(['simulate', 'github', '--event', 'pull_request', '--curl']);
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('x-hub-signature-256'));
    expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('pull_request'));
    consoleSpy.mockRestore();
  });
});
