declare module 'whois-json' {
  function whoisJson(domain: string): Promise<Record<string, any>>;
  export default whoisJson;
}
