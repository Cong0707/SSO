export type ApiResult<T> = { success: boolean; data?: T; message?: string };

let csrfToken = "";
export function setCsrf(value: string) {
  csrfToken = value;
}

export async function api<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  if (csrfToken && options.method && options.method !== "GET")
    headers.set("X-CSRF-Token", csrfToken);
  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "include",
  });
  const payload = (await response.json().catch(() => ({}))) as ApiResult<T> &
    Record<string, unknown>;
  if (!response.ok || payload.success === false)
    throw new Error(
      String(payload.message || payload.error_description || "请求失败"),
    );
  return (payload.data ?? payload) as T;
}

export async function apiForm<T>(path: string, form: FormData): Promise<T> {
  const headers = new Headers();
  if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
  const response = await fetch(path, {
    method: "POST",
    body: form,
    headers,
    credentials: "include",
  });
  const payload = (await response.json().catch(() => ({}))) as ApiResult<T>;
  if (!response.ok || payload.success === false)
    throw new Error(String(payload.message || "请求失败"));
  return (payload.data ?? payload) as T;
}
