// Astro 5's content image serializer drops falsy attributes, including alt="".
// Whitespace keeps a decorative alt attribute through serialization; authored
// descriptions are left intact. This avoids announcing asset URLs to readers.
export default function rehypeImageAlt() {
  return function walk(node) {
    if (node.type === 'element' && node.tagName === 'img') {
      node.properties ??= {};
      if (!node.properties.alt) node.properties.alt = ' ';
    }
    node.children?.forEach(walk);
  };
}
