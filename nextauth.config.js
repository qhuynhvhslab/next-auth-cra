import CredentialsProvider from "next-auth/providers/credentials";
import GitHubProvider from 'next-auth/providers/github'
import DiscordProvider from "next-auth/providers/discord";

let useSecureCookies = true;
export const authOptions = {

  secret: process.env.NEXTAUTH_SECRET,
  providers: [
    // CredentialsProvider({
    //   credentials: {
    //     Password: { placeholder: `type "password"`, type: "password" },
    //   },
    //   authorize(credentials) {
    //     if (credentials.Password === "password") {
    //       return {
    //         name: "John Doe",
    //         email: "john@doe.com",
    //         image: "https://www.fillmurray.com/200/200",
    //       };
    //     }
    //   },
    // }),
    GitHubProvider({
      clientId: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
    }),
    DiscordProvider({
      /* default should be [origin]/api/auth/callback/[provider] ~ https://next-auth.js.org/configuration/providers/oauth */
      clientId: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_SECRET,
    }),
  ],
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
    // async jwt({ token, user, account, profile }) {
    //   if (user) {
    //     token.profile = profile;
    //     token.user = user;
    //     token.provider = account?.provider;
    //   }

    //   return token;
    // },
    // async session({ session, token }) {
    //   console.log("session", session)
    //   if (token.provider === "admin-authenticate") {
    //     session.profile = token.profile || null;
    //     session.user = token.user;
    //     session.provider = token.provider;
    //     return session;
    //   } else {
    //     let userQuery;
    //     if (token.provider === "twitter") {
    //       userQuery = await prisma.whiteList.findFirst({
    //         where: {
    //           twitterId: token?.user?.id,
    //         },
    //       });
    //     }
    //     if (token.provider === "discord") {
    //       userQuery = await prisma.whiteList.findFirst({
    //         where: {
    //           discordId: token?.user?.id,
    //         },
    //       });
    //     }

    //     session.profile = token.profile || null;
    //     session.user = token.user;
    //     session.provider = token.provider;

    //     if (!session?.user?.userId) {
    //       session.user.address = userQuery?.wallet || "";
    //       session.user.userId = userQuery?.userId;
    //       session.user.uathUser = userQuery?.uathUser || "";
    //     }
    //     return session;
    //   }
    // },
  },
  theme: {
    logo: "/logo192.png",
    colorScheme: "light",
    brandColor: "#663399",
  },
  cookies: {
    sessionToken: {
      name: `${useSecureCookies ? '__Secure-' : ''}next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        domain: '.anomuragame.com',
        secure: useSecureCookies,
      },
    },
  },
};

// export const authOptions = {
//   providers: [

//     GitHubProvider({
//       clientId: process.env.GITHUB_ID,
//       clientSecret: process.env.GITHUB_SECRET,
//     }),
//   ],
//   debug: true,
//   // session: {
//   //   jwt: true,
//   //   maxAge: 60 * 60 * 24, // 7 days
//   // },
//   jwt: {
//     signingKey: NEXTAUTH_SECRET,
//   },
//   callbacks: {
//     signIn: async (user, account, profile) => {
//       // console.log("Provider: " + user?.account?.provider);

//       if (user?.account?.provider === "unstoppable-authenticate") {
//         let uathUser = user.credentials.uathUser;
//         const existingUser = await prisma.whiteList.findFirst({
//           where: {
//             uathUser: uathUser,
//           },
//         });
//         if (!existingUser) {
//           let error = `Unstoppable domain ${uathUser} is not linked.`;
//           console.log(error);
//           return `/quest-redirect?error=${error}`;
//         }

//         let credentials = user?.credentials;
//         let userInfo = user?.user;

//         if (
//           // credentials.address.toLowerCase() != userInfo.address.toLowerCase() ||
//           credentials.message != userInfo.message ||
//           credentials.signature != userInfo.signature
//         ) {
//           console.log("Invalid unstoppable authorization.");
//           let error = `Invalid unstoppable authorization.`;
//           return `/quest-redirect?error=${error}`;
//         }
//         return true;
//       }
//       if (user?.account?.provider === "discord") {
//         let discordId = user.account.providerAccountId;
//         const existingUser = await prisma.whiteList.findFirst({
//           where: {
//             discordId,
//           },
//         });

//         if (!existingUser) {
//           let error = `Discord ${user.profile.username}%23${user.profile.discriminator} not found in our database.`;
//           return `/quest-redirect?error=${error}`;
//         }
//         return true;
//       }

//       if (user.account.provider === "twitter") {
//         let twitterId = user.account.providerAccountId;

//         const existingUser = await prisma.whiteList.findFirst({
//           where: {
//             twitterId,
//           },
//         });

//         if (!existingUser) {
//           let error = `Twitter account ${user.user.name} not found in our database.`;
//           return `/quest-redirect?error=${error}`;
//         }
//         return true;
//       }

//       return true;
//     },
//     async redirect({ url, baseUrl }) {
//       return url;
//     },
//     async jwt({ token, user, account, profile }) {
//       if (user) {
//         token.profile = profile;
//         token.user = user;
//         token.provider = account?.provider;
//       }

//       return token;
//     },
//     async session({ session, token }) {
//       console.log("session", session)
//       if (token.provider === "admin-authenticate") {
//         session.profile = token.profile || null;
//         session.user = token.user;
//         session.provider = token.provider;
//         return session;
//       } else {
//         let userQuery;
//         if (token.provider === "twitter") {
//           userQuery = await prisma.whiteList.findFirst({
//             where: {
//               twitterId: token?.user?.id,
//             },
//           });
//         }
//         if (token.provider === "discord") {
//           userQuery = await prisma.whiteList.findFirst({
//             where: {
//               discordId: token?.user?.id,
//             },
//           });
//         }

//         session.profile = token.profile || null;
//         session.user = token.user;
//         session.provider = token.provider;

//         if (!session?.user?.userId) {
//           session.user.address = userQuery?.wallet || "";
//           session.user.userId = userQuery?.userId;
//           session.user.uathUser = userQuery?.uathUser || "";
//         }
//         return session;
//       }
//     },
//   },
//   secret: NEXTAUTH_SECRET,

// };
