export interface JwtUser {
  sub: string;
  id: string;
  email: string;
  iat: number;
  exp: number;
}
