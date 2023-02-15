import NextAuth from "next-auth/next";
// import { authConfig } from "../../nextauth.config";

import { authOptions } from "../../nextauth.config";
export default async function handler(req, res) {
  req.query.nextauth = req.params.nextauth.split("/");
  return await NextAuth(req, res, authOptions);
}
