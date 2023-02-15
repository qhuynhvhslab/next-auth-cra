import NextAuth from "next-auth/next";

export const authOptions = {
  providers: [
    /*   
        Update new nonce for next time authentication
        Authenticating by rebuilding the owner address from the signature and compare with the submitted address
    */
    // CredentialsProvider({
    //   id: "admin-authenticate",
    //   name: "admin-authenticate",
    //   type: "credentials",

    //   authorize: async (credentials, req) => {
    //     try {
    //       const { address, signature } = credentials;
    //       if (!address || !signature) throw new Error("Missing address or signature");

    //       let wallet = utils.getAddress(address);
    //       if (!wallet && !utils.isAddress(address))
    //         throw new Error("Invalid wallet address");

    //       const admin = await prisma.admin.findUnique({
    //         where: {
    //           wallet,
    //         },
    //       });

    //       if (!admin) throw new Error("Wallet address not belong to any admin!");

    //       const nonce = admin.nonce.trim();
    //       const msg = `${Enums.ADMIN_SIGN_MSG}: ${nonce}`;

    //       const msgBufferHex = ethUtil.bufferToHex(Buffer.from(msg, "utf8"));
    //       const originalAddress = recoverPersonalSignature({
    //         data: msgBufferHex,
    //         signature: signature,
    //       });

    //       if (originalAddress.toLowerCase() !== address.toLowerCase())
    //         throw new Error("Signature verification failed");

    //       const newNonce = CryptoJS.lib.WordArray.random(16).toString();

    //       let res = await prisma.Admin.update({
    //         where: {
    //           //wallet: { equals: originalAddress.toLowerCase(), mode: "insensitive" },
    //           id: admin.id,
    //         },
    //         data: {
    //           nonce: newNonce,
    //         },
    //       });

    //       if (!res) {
    //         console.error("cannot update new nonce");
    //       }

    //       console.log("Authenticated as admin successfully");
    //       return { address: originalAddress, isAdmin: true };
    //     } catch (error) {
    //       throw new Error(error);
    //     }
    //   },
    // }),
    // CredentialsProvider({
    //   id: "non-admin-authenticate",
    //   name: "Non-admin authentication",
    //   type: "credentials",
    //   authorize: async (credentials, req) => {
    //     try {
    //       console.log("Authenticating as user");
    //       let { address, signature } = credentials;

    //       if (!address || !signature) throw new Error("Missing address or signature");

    //       if (utils.getAddress(address) && !utils.isAddress(address))
    //         throw new Error("Invalid address");

    //       const user = await prisma.whiteList.findFirst({
    //         where: {
    //           wallet: { equals: address, mode: "insensitive" },
    //         },
    //       });

    //       if (!user) {
    //         throw new Error("This wallet account is not in our record.");
    //       }

    //       const msg = `${Enums.USER_SIGN_MSG}`;

    //       const msgBufferHex = ethUtil.bufferToHex(Buffer.from(msg, "utf8"));

    //       const originalAddress = recoverPersonalSignature({
    //         data: msgBufferHex,
    //         signature: signature.trim(),
    //       });

    //       if (originalAddress.toLowerCase() !== address.toLowerCase())
    //         throw new Error("Signature verification failed");

    //       console.log("Authenticated as user successfully");

    //       return { address: originalAddress, isAdmin: false, userId: user.userId };
    //     } catch (error) {
    //       console.log(error);
    //       throw error;
    //     }
    //   },
    // }),
    // CredentialsProvider({
    //   id: "unstoppable-authenticate",
    //   name: "Unstoppable authentication",
    //   type: "credentials",
    //   authorize: async (credentials, req) => {
    //     try {
    //       console.log("Authenticating as unstoppable user");
    //       let { uathUser, address, message, signature, authorization } = credentials;

    //       // if (!address || !uathUser || !authorization) {
    //       //     console.log("Missing unstoppable info");
    //       //     throw new Error("Missing unstoppable info");
    //       // }

    //       if (utils.getAddress(address) && !utils.isAddress(address))
    //         throw new Error("Invalid address");

    //       const user = await prisma.whiteList.findFirst({
    //         where: {
    //           uathUser,
    //         },
    //       });
    //       // let test = await uauth.user();
    //       // console.log("test", test)

    //       let type = "sig",
    //         version = "v1";

    //       const {
    //         address: originalAddress,
    //         message: originalMessage,
    //         signature: originalSignature,
    //       } = await uauth.getAuthorizationAccount(
    //         JSON.parse(authorization),
    //         type,
    //         version
    //       );

    //       console.log("Authenticated as user successfully");

    //       return {
    //         address,
    //         message,
    //         signature,
    //         isAdmin: false,
    //         userId: user?.userId,
    //         uauthUser: uathUser,
    //         originalAddress,
    //         originalMessage,
    //         originalSignature,
    //       };
    //     } catch (error) {
    //       console.log(error);
    //     }
    //   },
    // }),
    // CredentialsProvider({
    //   id: "email",
    //   // The name to display on the sign in form (e.g. 'Sign in with...')
    //   name: "Email",
    //   credentials: {
    //     email: {
    //       label: "email",
    //       type: "email",
    //       placeholder: "jsmith@example.com",
    //     },
    //     password: { label: "Password", type: "password" },
    //   },
    //   async authorize(credentials, req) {
    //     const { email, password } = credentials;

    //     // sanitize email field

    //     //check user and password
    //     if (!validateEmail(email)) {
    //       throw new Error("Invalid email.");
    //     }
    //     if (password.trim().length === 0) {
    //       throw new Error("Blank password.");
    //     }

    //     const currentUser = await prisma.whiteList.findFirst({
    //       where: {
    //         email,
    //       },
    //     });

    //     if (!currentUser) {
    //       throw new Error("This email account is not in our record.");
    //     }

    //     // bcrypt check
    //     const comparePassword = await bcrypt.compare(password, currentUser.password);
    //     if (!comparePassword) {
    //       throw new Error("Wrong password entered.");
    //     }

    //     return {
    //       address: currentUser?.wallet,
    //       isAdmin: false,
    //       userId: currentUser.userId,
    //       email: currentUser.email,
    //     };

    //     //   const res = await fetch('http://localhost:5287/api/tokens', {
    //     //     method: 'POST',
    //     //     body: JSON.stringify(payload),
    //     //     headers: {
    //     //       'Content-Type': 'application/json',
    //     //     },
    //     //   })

    //     //   const user = await res.json()
    //     //   if (!res.ok) {
    //     //     throw new Error(user.message)
    //     //   }
    //     //   // If no error and we have user data, return it
    //     //   if (res.ok && user) {
    //     //     return user
    //     //   }

    //     //   // Return null if user data could not be retrieved
    //     //   return null
    //   },
    // }),
    // DiscordProvider({

    //   clientId: await getVariableConfig("discordId"),
    //   clientSecret: await getVariableConfig("discordSecret"),
    // }),
    // TwitterProvider({
    //   clientId: await getVariableConfig("twitterId"),
    //   clientSecret: await getVariableConfig("twitterSecret"),
    //   version: "2.0",
    // }),
    GitHubProvider({
      clientId: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
    }),
  ],
  debug: false,
  session: {
    jwt: true,
    maxAge: 60 * 60 * 24, // 7 days
  },
  jwt: {
    signingKey: NEXTAUTH_SECRET,
  },
  callbacks: {
    signIn: async (user, account, profile) => {
      // console.log("Provider: " + user?.account?.provider);

      if (user?.account?.provider === "unstoppable-authenticate") {
        let uathUser = user.credentials.uathUser;
        const existingUser = await prisma.whiteList.findFirst({
          where: {
            uathUser: uathUser,
          },
        });
        if (!existingUser) {
          let error = `Unstoppable domain ${uathUser} is not linked.`;
          console.log(error);
          return `/quest-redirect?error=${error}`;
        }

        let credentials = user?.credentials;
        let userInfo = user?.user;

        if (
          // credentials.address.toLowerCase() != userInfo.address.toLowerCase() ||
          credentials.message != userInfo.message ||
          credentials.signature != userInfo.signature
        ) {
          console.log("Invalid unstoppable authorization.");
          let error = `Invalid unstoppable authorization.`;
          return `/quest-redirect?error=${error}`;
        }
        return true;
      }
      if (user?.account?.provider === "discord") {
        let discordId = user.account.providerAccountId;
        const existingUser = await prisma.whiteList.findFirst({
          where: {
            discordId,
          },
        });

        if (!existingUser) {
          let error = `Discord ${user.profile.username}%23${user.profile.discriminator} not found in our database.`;
          return `/quest-redirect?error=${error}`;
        }
        return true;
      }

      if (user.account.provider === "twitter") {
        let twitterId = user.account.providerAccountId;

        const existingUser = await prisma.whiteList.findFirst({
          where: {
            twitterId,
          },
        });

        if (!existingUser) {
          let error = `Twitter account ${user.user.name} not found in our database.`;
          return `/quest-redirect?error=${error}`;
        }
        return true;
      }

      return true;
    },
    async redirect({ url, baseUrl }) {
      return url;
    },
    async jwt({ token, user, account, profile }) {
      if (user) {
        token.profile = profile;
        token.user = user;
        token.provider = account?.provider;
      }

      return token;
    },
    async session({ session, token }) {
      console.log("session", session)
      if (token.provider === "admin-authenticate") {
        session.profile = token.profile || null;
        session.user = token.user;
        session.provider = token.provider;
        return session;
      } else {
        let userQuery;
        if (token.provider === "twitter") {
          userQuery = await prisma.whiteList.findFirst({
            where: {
              twitterId: token?.user?.id,
            },
          });
        }
        if (token.provider === "discord") {
          userQuery = await prisma.whiteList.findFirst({
            where: {
              discordId: token?.user?.id,
            },
          });
        }

        session.profile = token.profile || null;
        session.user = token.user;
        session.provider = token.provider;

        if (!session?.user?.userId) {
          session.user.address = userQuery?.wallet || "";
          session.user.userId = userQuery?.userId;
          session.user.uathUser = userQuery?.uathUser || "";
        }
        return session;
      }
    },
  },
  secret: NEXTAUTH_SECRET,
  // cookies: {
  //     sessionToken: {
  //         name: `${useSecureCookies ? '__Secure-' : ''}next-auth.session-token`,
  //         options: {
  //             httpOnly: true,
  //             sameSite: 'lax',
  //             path: '/',
  //             domain: '.anomuragame.com',
  //             secure: useSecureCookies,
  //         },
  //     },
  // },
};

import { authConfig } from "../../nextauth.config";

export default async function handler(req, res) {
  req.query.nextauth = req.params.nextauth.split("/");
  return await NextAuth(req, res, authConfig);
}
