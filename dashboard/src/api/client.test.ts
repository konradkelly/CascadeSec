import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// API_BASE is read from import.meta.env at module load, so each test that
// changes it re-imports the module after stubbing.
vi.mock('../auth/token', () => ({ readToken: vi.fn() }))

async function load(base: string | undefined, token: string | null) {
  vi.resetModules()
  vi.stubEnv('VITE_API_BASE_URL', base ?? '')
  const { readToken } = await import('../auth/token')
  vi.mocked(readToken).mockReturnValue(token)
  return import('./client')
}

function respond(status: number, body: unknown) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  })
}

function lastCall(): [string, RequestInit] {
  const [url, init] = vi.mocked(fetch).mock.calls[0]
  return [url as string, init as RequestInit]
}

beforeEach(() => {
  vi.stubGlobal('fetch', respond(200, {}))
})

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('request', () => {
  it('sends the bearer token on every call', async () => {
    const client = await load('https://api.example.test', 'tok-123')

    await client.listFindings('pr-1')

    const [url, init] = lastCall()
    expect(url).toBe('https://api.example.test/prs/pr-1/findings')
    expect(init.headers).toMatchObject({ authorization: 'Bearer tok-123' })
  })

  it('sends no authorization header without a token, and lets the API say 401', async () => {
    // The client cannot tell an expired session from auth never set up;
    // both surface as the API's 401, which is the one place that knows.
    const client = await load('https://api.example.test', null)

    await client.listFindings('pr-1')

    expect(lastCall()[1].headers).not.toHaveProperty('authorization')
  })

  it('strips a trailing slash from the base URL so paths do not double it', async () => {
    const client = await load('https://api.example.test/', 'tok')

    await client.listFindings('pr-1')

    expect(lastCall()[0]).toBe('https://api.example.test/prs/pr-1/findings')
  })

  it('encodes path segments, so an id with a slash cannot change the route', async () => {
    const client = await load('https://api.example.test', 'tok')

    await client.getFinding('owner/repo#12', 'a/b')

    expect(lastCall()[0]).toBe('https://api.example.test/prs/owner%2Frepo%2312/findings/a%2Fb')
  })

  it('refuses to call anything when the base URL is not configured', async () => {
    const client = await load(undefined, 'tok')

    await expect(client.listFindings('pr-1')).rejects.toMatchObject({
      name: 'ApiClientError',
      status: 0,
      message: expect.stringContaining('VITE_API_BASE_URL'),
    })
    expect(fetch).not.toHaveBeenCalled()
  })

  it('surfaces the API error message with its status', async () => {
    vi.stubGlobal('fetch', respond(409, { error: 'prerequisite f1 was rejected' }))
    const client = await load('https://api.example.test', 'tok')

    await expect(client.postReview('pr-1', 'f2', { action: 'approved' })).rejects.toMatchObject({
      name: 'ApiClientError',
      status: 409,
      message: 'prerequisite f1 was rejected',
    })
  })

  it('falls back to a generic message when the error body is not JSON', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: false, status: 502, json: () => Promise.reject(new SyntaxError()) }),
    )
    const client = await load('https://api.example.test', 'tok')

    await expect(client.listFindings('pr-1')).rejects.toMatchObject({ status: 502, message: 'Request failed (502)' })
  })

  it('posts a review as JSON with only what the API accepts', async () => {
    // No actor: the API takes the reviewer from the token. No diff: the
    // reviewer sends the whole corrected file and the API computes the diff.
    const client = await load('https://api.example.test', 'tok')

    await client.postReview('pr-1', 'f1', { action: 'edited', notes: 'tightened', edited_content: 'resource {}' })

    const [url, init] = lastCall()
    expect(url).toBe('https://api.example.test/prs/pr-1/findings/f1/review')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual({
      action: 'edited',
      notes: 'tightened',
      edited_content: 'resource {}',
    })
  })
})
