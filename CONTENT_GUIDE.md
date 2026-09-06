# Writing on ramveil.com

Writeups and projects use ordinary Markdown (`.md`) with YAML frontmatter. No imports, JSX, or component syntax is needed. Existing URLs, article layout, heading anchors, code highlighting, copy buttons, tables, and image optimization are retained.

## Writeups

Create `src/content/writeups/your-challenge/index.md`. Keep related images beside it.

```markdown
---
title: "Your challenge title"
description: "A short summary for the listing."
publishDate: 2026-09-05
read: 8
tags: ["Web", "CTF"]
img: "/assets/blog/your-cover.png"
img_alt: "A description of the cover"
featured: false
---

## Overview

Your introduction.

## Analysis

![A description of the evidence](./evidence.png)

## Solution

Your solution and fenced code blocks.
```

Keep the directory name when editing an existing post: it determines the public URL. Only one writeup is displayed as the featured entry. Writeups paginate automatically.

## Projects

Create `src/content/projects/your-project.md` using the same title, description, date, and tags fields. Projects use `image` for the cover, plus optional `order`, `isShow`, `video`, and `repo` fields:

```yaml
---
title: "Your project"
description: "What it does."
publishDate: 2026-09-05
image: "/assets/works/your-project.png"
tags: ["Security", "Python"]
order: 4
isShow: true
---
```

Use normal Markdown for the body. Existing frontmatter and body text were preserved during the migration, including the original project descriptions.

## Blogs

Blogs continue to support `.md` and `.mdx`. Existing interactive blog widgets need MDX and remain intact.

## Preview and validate

```sh
pnpm install --frozen-lockfile
pnpm dev
pnpm build
```

Development runs at `http://localhost:5200`. The build includes Astro's type check and generates the static site in `dist/`.

## Design

Shared color tokens are in `src/styles/global.css`. Navigation, cards, responsive layouts, and portfolio styling are in `src/styles/portfolio.css`. Article typography and geometry remain in the two existing article stylesheets.

Dark mode is the default; a saved light-mode preference is respected. Reduced motion uses the static tool stack. Local backups, comparison reports, and review screenshots are under `.review/` and are not part of the deployed site.
