import React from "react";
import { createRoot } from "react-dom/client";
import { App, ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import Console from "./app/Console";
import "./style.css";
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: "#2563eb",
          borderRadius: 10,
          fontFamily: "Inter, system-ui, sans-serif",
        },
        components: {
          Layout: { headerBg: "#fff", bodyBg: "#f4f7fc", siderBg: "#101e35" },
          Menu: { darkItemBg: "#101e35", darkItemSelectedBg: "#245ad2" },
        },
      }}
    >
      <App>
        <Console />
      </App>
    </ConfigProvider>
  </React.StrictMode>,
);
