{
    "builds" [
      {
        "src": "api/index.js",
        "use": "@vercel/node"
      }
    ],
    "routes" [
      {
        "src": "/(.*)",
        "dest": "/api/index.js"
      }
    ]
  }
  