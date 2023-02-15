import NextAuth from "next-auth/next";
import { authOptions } from "../../nextauth.config";
// import { authOptions } from "../../src/api/[...nextauth]";


export default async function handler(req, res) {
  const { nextauth, provider, ...rest } = req.query;
  req.query = { nextauth: [nextauth, provider], ...rest };
  return await NextAuth(req, res, authOptions);
}
