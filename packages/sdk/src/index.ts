export interface IdentityReadonlyClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

export class IdentityReadonlyClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: IdentityReadonlyClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async health() {
    return this.get("/health");
  }

  async roles() {
    return this.get("/admin/roles");
  }

  async organizations() {
    return this.get("/admin/organizations");
  }

  async user(id: number) {
    return this.get(`/admin/users/${id}`);
  }

  private async get(path: string) {
    const response = await this.fetchImpl(`${this.baseUrl}${path}`);
    if (!response.ok) {
      throw new Error(`Identity readonly request failed: ${response.status}`);
    }
    return response.json();
  }
}

