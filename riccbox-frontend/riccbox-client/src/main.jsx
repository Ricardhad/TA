import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import { Auth0Provider } from "@auth0/auth0-react";

// ❌ REMOVE: import dotenv from 'dotenv';
// ❌ REMOVE: dotenv.config();
// console.log("Vite Env Check:", import.meta.env.VITE_AUTH0_DOMAIN);
createRoot(document.getElementById("root")).render(
  <StrictMode>
    <Auth0Provider
      // ✅ VITE uses import.meta.env
      domain={import.meta.env.VITE_AUTH0_DOMAIN}
      clientId={import.meta.env.VITE_AUTH0_CLIENT_ID}
      authorizationParams={{ 
        redirect_uri: window.location.origin,
        // ✅ Add this back! It's the "Building ID" for your Jakarta VM
        audience: "https://richardgatewayta.duckdns.org",
      }}
    >
      <App />
    </Auth0Provider>
  </StrictMode>
);