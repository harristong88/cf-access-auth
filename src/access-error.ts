export class AccessError extends Error {
  constructor(public readonly code: string, public readonly status: 401 | 403 | 503 = 401) {
    super(status === 401 ? 'Unauthorized' : status === 403 ? 'Forbidden' : 'Authentication unavailable');
    this.name = 'AccessError';
  }
}
