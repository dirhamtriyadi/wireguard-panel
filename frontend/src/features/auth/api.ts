import { api } from "@/lib/api"

export interface LoginResult {
  token: string
  token_type: string
  expires_at: string
  username: string
}

interface ApiEnvelope<T> {
  success: boolean
  message: string
  data: T
}

export async function login(username: string, password: string): Promise<LoginResult> {
  const { data } = await api.post<ApiEnvelope<LoginResult>>("/auth/login", {
    username,
    password,
  })
  return data.data
}
