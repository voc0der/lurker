// Generate a simple SVG icon for PWA support
// Can be easily replaced with a custom logo later

function generateIcon(size = 512, backgroundColor = '#29BC9B', textColor = '#ffffff') {
  const fontSize = size * 0.6;
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <rect width="${size}" height="${size}" fill="${backgroundColor}" rx="${size * 0.1}"/>
  <text x="50%" y="50%" dominant-baseline="central" text-anchor="middle"
        font-family="Inter, -apple-system, sans-serif" font-size="${fontSize}"
        font-weight="700" fill="${textColor}">L</text>
</svg>`;

  return svg;
}

module.exports = { generateIcon };
