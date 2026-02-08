#!/usr/bin/env node
/**
 * Clean duplicate content from frontend index.html
 */

const fs = require('fs');
const path = require('path');

const INDEX_PATH = path.join(__dirname, '../web/portal/index.html');

// Read current index.html
let htmlContent = fs.readFileSync(INDEX_PATH, 'utf8');

// Remove duplicate <style> tag at the end
htmlContent = htmlContent.replace(/<style>[\s\S]*?<\/style>\s*<\/head>/g, '</head>');

// Fix the body closing tag issue
htmlContent = htmlContent.replace(/No newline at end of file[\s\S]*$/, '</body>\n</html>');

// Ensure proper closing
if (!htmlContent.endsWith('</html>')) {
    htmlContent += '\n</body>\n</html>';
}

// Write cleaned content
fs.writeFileSync(INDEX_PATH, htmlContent);
console.log('✅ Frontend cleaned successfully!');
console.log('📄 Removed duplicate styles');
console.log('🔧 Fixed file structure');