{
  "name": "bizflow-production-app",
  "version": "1.0.0",
  "private": true,
  "description": "BizFlow full-stack business management app with MySQL and security controls",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "node --watch src/server.js",
    "create-admin": "node scripts/create-admin.js",
    "check": "node --check src/server.js && node --check public/app.js && node --check scripts/create-admin.js"
  },
  "engines": { "node": ">=22" },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.4.7",
    "express": "^4.21.2",
    "express-rate-limit": "^7.5.0",
    "helmet": "^8.0.0",
    "jsonwebtoken": "^9.0.2",
    "mysql2": "^3.12.0"
  }
}
