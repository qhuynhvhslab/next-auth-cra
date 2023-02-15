import * as React from "react";
import Layout from "./components/layout";

import { SessionProvider } from "next-auth/react";

export default function App() {
  return (
    <SessionProvider>
      <Layout>
        <h1>React shared state test</h1>

      </Layout>
    </SessionProvider>
  );
}
