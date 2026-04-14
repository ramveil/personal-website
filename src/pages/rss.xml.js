import rss from "@astrojs/rss";
import { getCollection } from "astro:content";

export async function GET(context) {
  const blog = await getCollection('writeups');
  return rss({
    title: 'ramveil Writeups',
    description: 'Writeups and notes from ramvel',
    site: context.site,
    items: blog.map((post) => {
      const link = `/writeups/${post.id}/`;
      return {
        title: post.data.title,
        pubDate: post.data.publishDate,
        description: post.data.description,
        link,
        stylesheet: '/rss/pretty-feed-v3.xsl',
      };
    }),
  });
}
