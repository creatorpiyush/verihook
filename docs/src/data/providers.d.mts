export interface DocumentedProvider {
  id: string;
  name: string;
  aliases?: string[];
  region?: string;
  fn: string;
  entry: string;
  env: string;
  headers: string[];
  scheme: string;
  secret: string;
  tolerance?: string;
  eventType: string;
  notes: string[];
  handshake?: string;
  signable?: boolean;
  testSecret?: string;
  docs: string;
}

export declare const providers: DocumentedProvider[];
