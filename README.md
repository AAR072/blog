# blog

Personal security research blog built with Hugo and deployed to Cloudflare Pages.

## Setup

Clone with submodules to pull the theme:

```bash
git clone --recurse-submodules https://github.com/AAR072/blog
```

If you already cloned without submodules:

```bash
git submodule update --init
```

## Local development

```bash
hugo server
```

## Deployment

Build the site and deploy to Cloudflare Pages:

```bash
hugo --minify
npx wrangler pages deploy public --project-name=blog --branch=main --commit-dirty=true
```

Requires being authenticated with Wrangler:

```bash
npx wrangler login
```
