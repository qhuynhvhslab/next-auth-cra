import * as React from "react";
import styles from "./layout.module.css";

import { signIn, signOut, useSession } from "next-auth/react";

export default function Layout({ children }) {
  const session = useSession();

  console.log(session)
  return (
    <div className={styles.wrapper}>
      <header>
        <div className={styles.signedInStatus}>
          <div
            className={`nojs-show ${session?.status === "loading" ? styles.loading : styles.loaded
              }`}
          >
            {session?.status !== "authenticated" && (
              <>
                <span className={styles.notSignedInText}>
                  You are not signed in
                </span>
                <button
                  // href="/api/auth/signin"
                  className={styles.buttonPrimary}
                  onClick={async () => signIn("github", {
                    // callbackUrl: `${window.location.origin}`,
                  })}
                >
                  Github
                </button>
                <button
                  // href="/api/auth/signin"
                  className={styles.buttonPrimary}
                  onClick={async () => signIn("discord", {
                    // callbackUrl: `${window.location.origin}`,
                  })}
                >
                  Discord
                </button>
              </>
            )}
            {session?.status === "authenticated" && (
              <>
                {session.data.user.image && (
                  <img
                    alt={`${session.data.user.name}'s avatar`}
                    src={session.data.user.image}
                    className={styles.avatar}
                  />
                )}
                <span className={styles.signedInText}>
                  <small>Signed in as</small>
                  <br />
                  <strong>{session.data.user.email} </strong>
                  {session.data.user.name
                    ? `(${session.data.user.name})`
                    : null}
                </span>
                <a
                  href="/api/auth/signout"
                  className={styles.button}
                  onClick={(e) => {
                    e.preventDefault();
                    signOut();
                  }}
                >
                  Sign out
                </a>
              </>
            )}
          </div>
        </div>
      </header>
      <main>{children}</main>
    </div>
  );
}
