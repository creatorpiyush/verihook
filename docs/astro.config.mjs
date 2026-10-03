import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";

export default defineConfig({
  site: "https://creatorpiyush.github.io",
  base: "/verihook",
  integrations: [
    starlight({
      title: "verihook",
      description:
        "Verify webhook signatures from Stripe, GitHub, Shopify, Slack and 35+ providers in any JavaScript framework.",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/creatorpiyush/verihook",
        },
      ],
      editLink: {
        baseUrl: "https://github.com/creatorpiyush/verihook/edit/main/docs/",
      },
      lastUpdated: true,
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Getting started", slug: "getting-started" },
            { label: "Why the raw body matters", slug: "guides/raw-body" },
            { label: "Troubleshooting", slug: "troubleshooting" },
          ],
        },
        {
          label: "Frameworks",
          items: [{ autogenerate: { directory: "frameworks" } }],
        },
        {
          label: "Providers",
          collapsed: true,
          items: [{ autogenerate: { directory: "providers" } }],
        },
        {
          label: "Guides",
          items: [{ autogenerate: { directory: "guides" } }],
        },
        {
          label: "Reference",
          items: [{ autogenerate: { directory: "reference" } }],
        },
      ],
    }),
  ],
});
