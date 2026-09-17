"use strict";

// Vercel discovers serverless functions from the api directory. The Express
// application remains shared with the local Node.js entry point in server.js.
module.exports = require("../server");
