import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  integrations: [
    starlight({
      title: "Constellation",
      description:
        "Operate trusted private AI compute across the computers you control.",
      lastUpdated: true,
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/ZShamsi987/Constellation",
        },
      ],
      sidebar: [
        { label: "Overview", link: "/" },
        { label: "Getting started", link: "/getting-started/" },
        { label: "Feature status", link: "/feature-status/" },
        { label: "Security and privacy", link: "/security-and-privacy/" },
        { label: "APIs and SDKs", link: "/api-and-sdks/" },
        { label: "Contributing", link: "/contributing/" },
      ],
    }),
  ],
});
