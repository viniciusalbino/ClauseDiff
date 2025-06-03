"use strict";
/*
 * ATTENTION: An "eval-source-map" devtool has been used.
 * This devtool is neither made for production nor for readable output files.
 * It uses "eval()" calls to create a separate source file with attached SourceMaps in the browser devtools.
 * If you are trying to read the output file, select a different devtool (https://webpack.js.org/configuration/devtool/)
 * or disable the default devtool with "devtool: false".
 * If you are looking for production-ready output files, see mode: "production" (https://webpack.js.org/configuration/mode/).
 */
(() => {
var exports = {};
exports.id = "app/auth/[...nextauth]/route";
exports.ids = ["app/auth/[...nextauth]/route"];
exports.modules = {

/***/ "@prisma/client":
/*!*********************************!*\
  !*** external "@prisma/client" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@prisma/client");

/***/ }),

/***/ "../../client/components/action-async-storage.external":
/*!*******************************************************************************!*\
  !*** external "next/dist/client/components/action-async-storage.external.js" ***!
  \*******************************************************************************/
/***/ ((module) => {

module.exports = require("next/dist/client/components/action-async-storage.external.js");

/***/ }),

/***/ "../../client/components/request-async-storage.external":
/*!********************************************************************************!*\
  !*** external "next/dist/client/components/request-async-storage.external.js" ***!
  \********************************************************************************/
/***/ ((module) => {

module.exports = require("next/dist/client/components/request-async-storage.external.js");

/***/ }),

/***/ "../../client/components/static-generation-async-storage.external":
/*!******************************************************************************************!*\
  !*** external "next/dist/client/components/static-generation-async-storage.external.js" ***!
  \******************************************************************************************/
/***/ ((module) => {

module.exports = require("next/dist/client/components/static-generation-async-storage.external.js");

/***/ }),

/***/ "next/dist/compiled/next-server/app-page.runtime.dev.js":
/*!*************************************************************************!*\
  !*** external "next/dist/compiled/next-server/app-page.runtime.dev.js" ***!
  \*************************************************************************/
/***/ ((module) => {

module.exports = require("next/dist/compiled/next-server/app-page.runtime.dev.js");

/***/ }),

/***/ "next/dist/compiled/next-server/app-route.runtime.dev.js":
/*!**************************************************************************!*\
  !*** external "next/dist/compiled/next-server/app-route.runtime.dev.js" ***!
  \**************************************************************************/
/***/ ((module) => {

module.exports = require("next/dist/compiled/next-server/app-route.runtime.dev.js");

/***/ }),

/***/ "assert":
/*!*************************!*\
  !*** external "assert" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("assert");

/***/ }),

/***/ "buffer":
/*!*************************!*\
  !*** external "buffer" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("buffer");

/***/ }),

/***/ "crypto":
/*!*************************!*\
  !*** external "crypto" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("crypto");

/***/ }),

/***/ "events":
/*!*************************!*\
  !*** external "events" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("events");

/***/ }),

/***/ "http":
/*!***********************!*\
  !*** external "http" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("http");

/***/ }),

/***/ "https":
/*!************************!*\
  !*** external "https" ***!
  \************************/
/***/ ((module) => {

module.exports = require("https");

/***/ }),

/***/ "querystring":
/*!******************************!*\
  !*** external "querystring" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("querystring");

/***/ }),

/***/ "url":
/*!**********************!*\
  !*** external "url" ***!
  \**********************/
/***/ ((module) => {

module.exports = require("url");

/***/ }),

/***/ "util":
/*!***********************!*\
  !*** external "util" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("util");

/***/ }),

/***/ "zlib":
/*!***********************!*\
  !*** external "zlib" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("zlib");

/***/ }),

/***/ "(rsc)/./node_modules/next/dist/build/webpack/loaders/next-app-loader.js?name=app%2Fauth%2F%5B...nextauth%5D%2Froute&page=%2Fauth%2F%5B...nextauth%5D%2Froute&appPaths=&pagePath=private-next-app-dir%2Fauth%2F%5B...nextauth%5D%2Froute.ts&appDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff%2Fapp&pageExtensions=tsx&pageExtensions=ts&pageExtensions=jsx&pageExtensions=js&rootDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff&isDev=true&tsconfigPath=tsconfig.json&basePath=&assetPrefix=&nextConfigOutput=&preferredRegion=&middlewareConfig=e30%3D!":
/*!********************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************!*\
  !*** ./node_modules/next/dist/build/webpack/loaders/next-app-loader.js?name=app%2Fauth%2F%5B...nextauth%5D%2Froute&page=%2Fauth%2F%5B...nextauth%5D%2Froute&appPaths=&pagePath=private-next-app-dir%2Fauth%2F%5B...nextauth%5D%2Froute.ts&appDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff%2Fapp&pageExtensions=tsx&pageExtensions=ts&pageExtensions=jsx&pageExtensions=js&rootDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff&isDev=true&tsconfigPath=tsconfig.json&basePath=&assetPrefix=&nextConfigOutput=&preferredRegion=&middlewareConfig=e30%3D! ***!
  \********************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   originalPathname: () => (/* binding */ originalPathname),\n/* harmony export */   patchFetch: () => (/* binding */ patchFetch),\n/* harmony export */   requestAsyncStorage: () => (/* binding */ requestAsyncStorage),\n/* harmony export */   routeModule: () => (/* binding */ routeModule),\n/* harmony export */   serverHooks: () => (/* binding */ serverHooks),\n/* harmony export */   staticGenerationAsyncStorage: () => (/* binding */ staticGenerationAsyncStorage)\n/* harmony export */ });\n/* harmony import */ var next_dist_server_future_route_modules_app_route_module_compiled__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! next/dist/server/future/route-modules/app-route/module.compiled */ \"(rsc)/./node_modules/next/dist/server/future/route-modules/app-route/module.compiled.js\");\n/* harmony import */ var next_dist_server_future_route_modules_app_route_module_compiled__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(next_dist_server_future_route_modules_app_route_module_compiled__WEBPACK_IMPORTED_MODULE_0__);\n/* harmony import */ var next_dist_server_future_route_kind__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! next/dist/server/future/route-kind */ \"(rsc)/./node_modules/next/dist/server/future/route-kind.js\");\n/* harmony import */ var next_dist_server_lib_patch_fetch__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! next/dist/server/lib/patch-fetch */ \"(rsc)/./node_modules/next/dist/server/lib/patch-fetch.js\");\n/* harmony import */ var next_dist_server_lib_patch_fetch__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(next_dist_server_lib_patch_fetch__WEBPACK_IMPORTED_MODULE_2__);\n/* harmony import */ var _Users_viniciusalbino_Documents_GitHub_clausediff_app_auth_nextauth_route_ts__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./app/auth/[...nextauth]/route.ts */ \"(rsc)/./app/auth/[...nextauth]/route.ts\");\n\n\n\n\n// We inject the nextConfigOutput here so that we can use them in the route\n// module.\nconst nextConfigOutput = \"\"\nconst routeModule = new next_dist_server_future_route_modules_app_route_module_compiled__WEBPACK_IMPORTED_MODULE_0__.AppRouteRouteModule({\n    definition: {\n        kind: next_dist_server_future_route_kind__WEBPACK_IMPORTED_MODULE_1__.RouteKind.APP_ROUTE,\n        page: \"/auth/[...nextauth]/route\",\n        pathname: \"/auth/[...nextauth]\",\n        filename: \"route\",\n        bundlePath: \"app/auth/[...nextauth]/route\"\n    },\n    resolvedPagePath: \"/Users/viniciusalbino/Documents/GitHub/clausediff/app/auth/[...nextauth]/route.ts\",\n    nextConfigOutput,\n    userland: _Users_viniciusalbino_Documents_GitHub_clausediff_app_auth_nextauth_route_ts__WEBPACK_IMPORTED_MODULE_3__\n});\n// Pull out the exports that we need to expose from the module. This should\n// be eliminated when we've moved the other routes to the new format. These\n// are used to hook into the route.\nconst { requestAsyncStorage, staticGenerationAsyncStorage, serverHooks } = routeModule;\nconst originalPathname = \"/auth/[...nextauth]/route\";\nfunction patchFetch() {\n    return (0,next_dist_server_lib_patch_fetch__WEBPACK_IMPORTED_MODULE_2__.patchFetch)({\n        serverHooks,\n        staticGenerationAsyncStorage\n    });\n}\n\n\n//# sourceMappingURL=app-route.js.map//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiKHJzYykvLi9ub2RlX21vZHVsZXMvbmV4dC9kaXN0L2J1aWxkL3dlYnBhY2svbG9hZGVycy9uZXh0LWFwcC1sb2FkZXIuanM/bmFtZT1hcHAlMkZhdXRoJTJGJTVCLi4ubmV4dGF1dGglNUQlMkZyb3V0ZSZwYWdlPSUyRmF1dGglMkYlNUIuLi5uZXh0YXV0aCU1RCUyRnJvdXRlJmFwcFBhdGhzPSZwYWdlUGF0aD1wcml2YXRlLW5leHQtYXBwLWRpciUyRmF1dGglMkYlNUIuLi5uZXh0YXV0aCU1RCUyRnJvdXRlLnRzJmFwcERpcj0lMkZVc2VycyUyRnZpbmljaXVzYWxiaW5vJTJGRG9jdW1lbnRzJTJGR2l0SHViJTJGY2xhdXNlZGlmZiUyRmFwcCZwYWdlRXh0ZW5zaW9ucz10c3gmcGFnZUV4dGVuc2lvbnM9dHMmcGFnZUV4dGVuc2lvbnM9anN4JnBhZ2VFeHRlbnNpb25zPWpzJnJvb3REaXI9JTJGVXNlcnMlMkZ2aW5pY2l1c2FsYmlubyUyRkRvY3VtZW50cyUyRkdpdEh1YiUyRmNsYXVzZWRpZmYmaXNEZXY9dHJ1ZSZ0c2NvbmZpZ1BhdGg9dHNjb25maWcuanNvbiZiYXNlUGF0aD0mYXNzZXRQcmVmaXg9Jm5leHRDb25maWdPdXRwdXQ9JnByZWZlcnJlZFJlZ2lvbj0mbWlkZGxld2FyZUNvbmZpZz1lMzAlM0QhIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7OztBQUFzRztBQUN2QztBQUNjO0FBQ2lDO0FBQzlHO0FBQ0E7QUFDQTtBQUNBLHdCQUF3QixnSEFBbUI7QUFDM0M7QUFDQSxjQUFjLHlFQUFTO0FBQ3ZCO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsS0FBSztBQUNMO0FBQ0E7QUFDQSxZQUFZO0FBQ1osQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBLFFBQVEsaUVBQWlFO0FBQ3pFO0FBQ0E7QUFDQSxXQUFXLDRFQUFXO0FBQ3RCO0FBQ0E7QUFDQSxLQUFLO0FBQ0w7QUFDdUg7O0FBRXZIIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vY2xhdXNlZGlmZi0tLWRvY3VtZW50LWNvbXBhcmlzb24tdG9vbC8/OWQ0YSJdLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBBcHBSb3V0ZVJvdXRlTW9kdWxlIH0gZnJvbSBcIm5leHQvZGlzdC9zZXJ2ZXIvZnV0dXJlL3JvdXRlLW1vZHVsZXMvYXBwLXJvdXRlL21vZHVsZS5jb21waWxlZFwiO1xuaW1wb3J0IHsgUm91dGVLaW5kIH0gZnJvbSBcIm5leHQvZGlzdC9zZXJ2ZXIvZnV0dXJlL3JvdXRlLWtpbmRcIjtcbmltcG9ydCB7IHBhdGNoRmV0Y2ggYXMgX3BhdGNoRmV0Y2ggfSBmcm9tIFwibmV4dC9kaXN0L3NlcnZlci9saWIvcGF0Y2gtZmV0Y2hcIjtcbmltcG9ydCAqIGFzIHVzZXJsYW5kIGZyb20gXCIvVXNlcnMvdmluaWNpdXNhbGJpbm8vRG9jdW1lbnRzL0dpdEh1Yi9jbGF1c2VkaWZmL2FwcC9hdXRoL1suLi5uZXh0YXV0aF0vcm91dGUudHNcIjtcbi8vIFdlIGluamVjdCB0aGUgbmV4dENvbmZpZ091dHB1dCBoZXJlIHNvIHRoYXQgd2UgY2FuIHVzZSB0aGVtIGluIHRoZSByb3V0ZVxuLy8gbW9kdWxlLlxuY29uc3QgbmV4dENvbmZpZ091dHB1dCA9IFwiXCJcbmNvbnN0IHJvdXRlTW9kdWxlID0gbmV3IEFwcFJvdXRlUm91dGVNb2R1bGUoe1xuICAgIGRlZmluaXRpb246IHtcbiAgICAgICAga2luZDogUm91dGVLaW5kLkFQUF9ST1VURSxcbiAgICAgICAgcGFnZTogXCIvYXV0aC9bLi4ubmV4dGF1dGhdL3JvdXRlXCIsXG4gICAgICAgIHBhdGhuYW1lOiBcIi9hdXRoL1suLi5uZXh0YXV0aF1cIixcbiAgICAgICAgZmlsZW5hbWU6IFwicm91dGVcIixcbiAgICAgICAgYnVuZGxlUGF0aDogXCJhcHAvYXV0aC9bLi4ubmV4dGF1dGhdL3JvdXRlXCJcbiAgICB9LFxuICAgIHJlc29sdmVkUGFnZVBhdGg6IFwiL1VzZXJzL3ZpbmljaXVzYWxiaW5vL0RvY3VtZW50cy9HaXRIdWIvY2xhdXNlZGlmZi9hcHAvYXV0aC9bLi4ubmV4dGF1dGhdL3JvdXRlLnRzXCIsXG4gICAgbmV4dENvbmZpZ091dHB1dCxcbiAgICB1c2VybGFuZFxufSk7XG4vLyBQdWxsIG91dCB0aGUgZXhwb3J0cyB0aGF0IHdlIG5lZWQgdG8gZXhwb3NlIGZyb20gdGhlIG1vZHVsZS4gVGhpcyBzaG91bGRcbi8vIGJlIGVsaW1pbmF0ZWQgd2hlbiB3ZSd2ZSBtb3ZlZCB0aGUgb3RoZXIgcm91dGVzIHRvIHRoZSBuZXcgZm9ybWF0LiBUaGVzZVxuLy8gYXJlIHVzZWQgdG8gaG9vayBpbnRvIHRoZSByb3V0ZS5cbmNvbnN0IHsgcmVxdWVzdEFzeW5jU3RvcmFnZSwgc3RhdGljR2VuZXJhdGlvbkFzeW5jU3RvcmFnZSwgc2VydmVySG9va3MgfSA9IHJvdXRlTW9kdWxlO1xuY29uc3Qgb3JpZ2luYWxQYXRobmFtZSA9IFwiL2F1dGgvWy4uLm5leHRhdXRoXS9yb3V0ZVwiO1xuZnVuY3Rpb24gcGF0Y2hGZXRjaCgpIHtcbiAgICByZXR1cm4gX3BhdGNoRmV0Y2goe1xuICAgICAgICBzZXJ2ZXJIb29rcyxcbiAgICAgICAgc3RhdGljR2VuZXJhdGlvbkFzeW5jU3RvcmFnZVxuICAgIH0pO1xufVxuZXhwb3J0IHsgcm91dGVNb2R1bGUsIHJlcXVlc3RBc3luY1N0b3JhZ2UsIHN0YXRpY0dlbmVyYXRpb25Bc3luY1N0b3JhZ2UsIHNlcnZlckhvb2tzLCBvcmlnaW5hbFBhdGhuYW1lLCBwYXRjaEZldGNoLCAgfTtcblxuLy8jIHNvdXJjZU1hcHBpbmdVUkw9YXBwLXJvdXRlLmpzLm1hcCJdLCJuYW1lcyI6W10sInNvdXJjZVJvb3QiOiIifQ==\n//# sourceURL=webpack-internal:///(rsc)/./node_modules/next/dist/build/webpack/loaders/next-app-loader.js?name=app%2Fauth%2F%5B...nextauth%5D%2Froute&page=%2Fauth%2F%5B...nextauth%5D%2Froute&appPaths=&pagePath=private-next-app-dir%2Fauth%2F%5B...nextauth%5D%2Froute.ts&appDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff%2Fapp&pageExtensions=tsx&pageExtensions=ts&pageExtensions=jsx&pageExtensions=js&rootDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff&isDev=true&tsconfigPath=tsconfig.json&basePath=&assetPrefix=&nextConfigOutput=&preferredRegion=&middlewareConfig=e30%3D!\n");

/***/ }),

/***/ "(rsc)/./app/auth/[...nextauth]/route.ts":
/*!*****************************************!*\
  !*** ./app/auth/[...nextauth]/route.ts ***!
  \*****************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export */ __webpack_require__.d(__webpack_exports__, {\n/* harmony export */   GET: () => (/* binding */ handler),\n/* harmony export */   POST: () => (/* binding */ handler)\n/* harmony export */ });\n/* harmony import */ var next_auth__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! next-auth */ \"(rsc)/./node_modules/next-auth/index.js\");\n/* harmony import */ var next_auth__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(next_auth__WEBPACK_IMPORTED_MODULE_0__);\n/* harmony import */ var _next_auth_prisma_adapter__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @next-auth/prisma-adapter */ \"(rsc)/./node_modules/@next-auth/prisma-adapter/dist/index.js\");\n/* harmony import */ var _prisma_client__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! @prisma/client */ \"@prisma/client\");\n/* harmony import */ var _prisma_client__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_prisma_client__WEBPACK_IMPORTED_MODULE_2__);\n/* harmony import */ var next_auth_providers_google__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! next-auth/providers/google */ \"(rsc)/./node_modules/next-auth/providers/google.js\");\n/* harmony import */ var next_auth_providers_credentials__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! next-auth/providers/credentials */ \"(rsc)/./node_modules/next-auth/providers/credentials.js\");\n/* harmony import */ var bcryptjs__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! bcryptjs */ \"(rsc)/./node_modules/bcryptjs/index.js\");\n/* harmony import */ var bcryptjs__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(bcryptjs__WEBPACK_IMPORTED_MODULE_5__);\n/* harmony import */ var zod__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! zod */ \"(rsc)/./node_modules/zod/dist/esm/index.js\");\n/**\n * Auth route para autenticação com NextAuth v4 (Next.js 14 App Router).\n *\n * POLÍTICA DE AUDITORIA E LOGGING:\n * - Este endpoint implementa logging/auditoria de eventos de autenticação (login, logout, falha, etc.)\n *   para fins de segurança, rastreabilidade e compliance (LGPD/GDPR).\n * - O logging é controlado pela feature flag de ambiente AUDIT_LOGGING_ENABLED.\n *   - Para ativar: defina AUDIT_LOGGING_ENABLED=on no .env\n *   - Por padrão, o log está DESLIGADO para evitar custos/desempenho no MVP.\n * - Os eventos são registrados na tabela AuditLog do banco via Prisma.\n * - Falhas no log NÃO afetam o fluxo de autenticação.\n *\n * Para ativar o login Google OAuth, defina GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET no .env\n * Exemplo:\n *   GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com\n *   GOOGLE_CLIENT_SECRET=xxxx\n */ \n\n\n\n\n\n\nconst prisma = new _prisma_client__WEBPACK_IMPORTED_MODULE_2__.PrismaClient();\n// Feature flag para logging de auditoria\nconst AUDIT_LOGGING_ENABLED = process.env.AUDIT_LOGGING_ENABLED === \"on\";\n// Função utilitária para registrar eventos de auditoria\nasync function logEvent({ userId, eventType, ip, userAgent, details }) {\n    if (!AUDIT_LOGGING_ENABLED) return;\n    try {\n        await prisma.auditLog.create({\n            data: {\n                userId,\n                eventType,\n                ip: ip || null,\n                userAgent: userAgent || null,\n                details\n            }\n        });\n    } catch (err) {\n        console.error(\"Erro ao registrar evento de auditoria:\", err);\n    }\n}\nconst credentialsSchema = zod__WEBPACK_IMPORTED_MODULE_6__.z.object({\n    email: zod__WEBPACK_IMPORTED_MODULE_6__.z.string().email(),\n    password: zod__WEBPACK_IMPORTED_MODULE_6__.z.string().min(6)\n});\nconst authOptions = {\n    adapter: (0,_next_auth_prisma_adapter__WEBPACK_IMPORTED_MODULE_1__.PrismaAdapter)(prisma),\n    providers: [\n        (0,next_auth_providers_credentials__WEBPACK_IMPORTED_MODULE_4__[\"default\"])({\n            name: \"Email e Senha\",\n            credentials: {\n                email: {\n                    label: \"Email\",\n                    type: \"email\",\n                    placeholder: \"seu@email.com\"\n                },\n                password: {\n                    label: \"Senha\",\n                    type: \"password\"\n                }\n            },\n            async authorize (credentials) {\n                const parsed = credentialsSchema.safeParse(credentials);\n                if (!parsed.success) {\n                    throw new Error(\"Credenciais inv\\xe1lidas\");\n                }\n                const { email, password } = parsed.data;\n                const user = await prisma.user.findUnique({\n                    where: {\n                        email\n                    }\n                });\n                if (!user || !user.password) {\n                    await logEvent({\n                        eventType: \"login_failed\",\n                        details: {\n                            email\n                        }\n                    });\n                    throw new Error(\"Usu\\xe1rio ou senha inv\\xe1lidos\");\n                }\n                const isValid = await bcryptjs__WEBPACK_IMPORTED_MODULE_5___default().compare(password, user.password);\n                if (!isValid) {\n                    await logEvent({\n                        userId: user.id,\n                        eventType: \"login_failed\",\n                        details: {\n                            email\n                        }\n                    });\n                    throw new Error(\"Usu\\xe1rio ou senha inv\\xe1lidos\");\n                }\n                return {\n                    id: user.id,\n                    email: user.email,\n                    name: `${user.firstName} ${user.lastName}`\n                };\n            }\n        }),\n        ...process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET ? [\n            (0,next_auth_providers_google__WEBPACK_IMPORTED_MODULE_3__[\"default\"])({\n                clientId: process.env.GOOGLE_CLIENT_ID,\n                clientSecret: process.env.GOOGLE_CLIENT_SECRET,\n                authorization: {\n                    params: {\n                        scope: \"openid email profile\"\n                    }\n                }\n            })\n        ] : []\n    ],\n    session: {\n        strategy: \"jwt\"\n    },\n    pages: {\n        signIn: \"/login\",\n        error: \"/login\"\n    },\n    callbacks: {\n        async signIn ({ user }) {\n            await logEvent({\n                userId: user?.id,\n                eventType: \"login_success\"\n            });\n            return true;\n        },\n        async jwt ({ token, user, account }) {\n            if (account && user) {\n                token.id = user.id;\n            }\n            return token;\n        },\n        async session ({ session, token }) {\n            if (token && session.user) {\n                session.user.id = token.id;\n            }\n            return session;\n        }\n    },\n    events: {\n        async signIn (message) {\n            if (message.user) {\n                await logEvent({\n                    userId: message.user.id,\n                    eventType: \"login_event_success\"\n                });\n            }\n        },\n        async signOut (message) {\n            if (message.token) {\n                await logEvent({\n                    userId: message.token.sub,\n                    eventType: \"logout_event\"\n                });\n            }\n        }\n    }\n};\nconst handler = next_auth__WEBPACK_IMPORTED_MODULE_0___default()(authOptions);\n\n//# sourceURL=[module]\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiKHJzYykvLi9hcHAvYXV0aC9bLi4ubmV4dGF1dGhdL3JvdXRlLnRzIiwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7Ozs7OztBQUFBOzs7Ozs7Ozs7Ozs7Ozs7O0NBZ0JDLEdBRWdDO0FBQ3lCO0FBQ1o7QUFDVTtBQUNVO0FBQ3BDO0FBQ047QUFHeEIsTUFBTU8sU0FBUyxJQUFJTCx3REFBWUE7QUFFL0IseUNBQXlDO0FBQ3pDLE1BQU1NLHdCQUF3QkMsUUFBUUMsR0FBRyxDQUFDRixxQkFBcUIsS0FBSztBQUVwRSx3REFBd0Q7QUFDeEQsZUFBZUcsU0FBUyxFQUFFQyxNQUFNLEVBQUVDLFNBQVMsRUFBRUMsRUFBRSxFQUFFQyxTQUFTLEVBQUVDLE9BQU8sRUFBd0c7SUFDekssSUFBSSxDQUFDUix1QkFBdUI7SUFDNUIsSUFBSTtRQUNGLE1BQU1ELE9BQU9VLFFBQVEsQ0FBQ0MsTUFBTSxDQUFDO1lBQzNCQyxNQUFNO2dCQUNKUDtnQkFDQUM7Z0JBQ0FDLElBQUlBLE1BQU07Z0JBQ1ZDLFdBQVdBLGFBQWE7Z0JBQ3hCQztZQUNGO1FBQ0Y7SUFDRixFQUFFLE9BQU9JLEtBQUs7UUFDWkMsUUFBUUMsS0FBSyxDQUFDLDBDQUEwQ0Y7SUFDMUQ7QUFDRjtBQUVBLE1BQU1HLG9CQUFvQmpCLHlDQUFRLENBQUM7SUFDakNtQixPQUFPbkIseUNBQVEsR0FBR21CLEtBQUs7SUFDdkJFLFVBQVVyQix5Q0FBUSxHQUFHc0IsR0FBRyxDQUFDO0FBQzNCO0FBRUEsTUFBTUMsY0FBYztJQUNsQkMsU0FBUzdCLHdFQUFhQSxDQUFDTTtJQUN2QndCLFdBQVc7UUFDVDNCLDJFQUFtQkEsQ0FBQztZQUNsQjRCLE1BQU07WUFDTkMsYUFBYTtnQkFDWFIsT0FBTztvQkFBRVMsT0FBTztvQkFBU0MsTUFBTTtvQkFBU0MsYUFBYTtnQkFBZ0I7Z0JBQ3JFVCxVQUFVO29CQUFFTyxPQUFPO29CQUFTQyxNQUFNO2dCQUFXO1lBQy9DO1lBQ0EsTUFBTUUsV0FBVUosV0FBVztnQkFDekIsTUFBTUssU0FB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L2NsYXVzZWRpZmYtLS1kb2N1bWVudC1jb21wYXJpc29uLXRvb2wvLi9hcHAvYXV0aC9bLi4ubmV4dGF1dGhdL3JvdXRlLnRzP2EyZWMiXSwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBBdXRoIHJvdXRlIHBhcmEgYXV0ZW50aWNhw6fDo28gY29tIE5leHRBdXRoIHY0IChOZXh0LmpzIDE0IEFwcCBSb3V0ZXIpLlxuICpcbiAqIFBPTMONVElDQSBERSBBVURJVE9SSUEgRSBMT0dHSU5HOlxuICogLSBFc3RlIGVuZHBvaW50IGltcGxlbWVudGEgbG9nZ2luZy9hdWRpdG9yaWEgZGUgZXZlbnRvcyBkZSBhdXRlbnRpY2HDp8OjbyAobG9naW4sIGxvZ291dCwgZmFsaGEsIGV0Yy4pXG4gKiAgIHBhcmEgZmlucyBkZSBzZWd1cmFuw6dhLCByYXN0cmVhYmlsaWRhZGUgZSBjb21wbGlhbmNlIChMR1BEL0dEUFIpLlxuICogLSBPIGxvZ2dpbmcgw6kgY29udHJvbGFkbyBwZWxhIGZlYXR1cmUgZmxhZyBkZSBhbWJpZW50ZSBBVURJVF9MT0dHSU5HX0VOQUJMRUQuXG4gKiAgIC0gUGFyYSBhdGl2YXI6IGRlZmluYSBBVURJVF9MT0dHSU5HX0VOQUJMRUQ9b24gbm8gLmVudlxuICogICAtIFBvciBwYWRyw6NvLCBvIGxvZyBlc3TDoSBERVNMSUdBRE8gcGFyYSBldml0YXIgY3VzdG9zL2Rlc2VtcGVuaG8gbm8gTVZQLlxuICogLSBPcyBldmVudG9zIHPDo28gcmVnaXN0cmFkb3MgbmEgdGFiZWxhIEF1ZGl0TG9nIGRvIGJhbmNvIHZpYSBQcmlzbWEuXG4gKiAtIEZhbGhhcyBubyBsb2cgTsODTyBhZmV0YW0gbyBmbHV4byBkZSBhdXRlbnRpY2HDp8Ojby5cbiAqXG4gKiBQYXJhIGF0aXZhciBvIGxvZ2luIEdvb2dsZSBPQXV0aCwgZGVmaW5hIEdPT0dMRV9DTElFTlRfSUQgZSBHT09HTEVfQ0xJRU5UX1NFQ1JFVCBubyAuZW52XG4gKiBFeGVtcGxvOlxuICogICBHT09HTEVfQ0xJRU5UX0lEPXh4eHguYXBwcy5nb29nbGV1c2VyY29udGVudC5jb21cbiAqICAgR09PR0xFX0NMSUVOVF9TRUNSRVQ9eHh4eFxuICovXG5cbmltcG9ydCBOZXh0QXV0aCBmcm9tIFwibmV4dC1hdXRoXCI7XG5pbXBvcnQgeyBQcmlzbWFBZGFwdGVyIH0gZnJvbSBcIkBuZXh0LWF1dGgvcHJpc21hLWFkYXB0ZXJcIjtcbmltcG9ydCB7IFByaXNtYUNsaWVudCB9IGZyb20gXCJAcHJpc21hL2NsaWVudFwiO1xuaW1wb3J0IEdvb2dsZVByb3ZpZGVyIGZyb20gXCJuZXh0LWF1dGgvcHJvdmlkZXJzL2dvb2dsZVwiO1xuaW1wb3J0IENyZWRlbnRpYWxzUHJvdmlkZXIgZnJvbSBcIm5leHQtYXV0aC9wcm92aWRlcnMvY3JlZGVudGlhbHNcIjtcbmltcG9ydCBiY3J5cHQgZnJvbSBcImJjcnlwdGpzXCI7XG5pbXBvcnQgeyB6IH0gZnJvbSBcInpvZFwiO1xuXG5cbmNvbnN0IHByaXNtYSA9IG5ldyBQcmlzbWFDbGllbnQoKTtcblxuLy8gRmVhdHVyZSBmbGFnIHBhcmEgbG9nZ2luZyBkZSBhdWRpdG9yaWFcbmNvbnN0IEFVRElUX0xPR0dJTkdfRU5BQkxFRCA9IHByb2Nlc3MuZW52LkFVRElUX0xPR0dJTkdfRU5BQkxFRCA9PT0gXCJvblwiO1xuXG4vLyBGdW7Dp8OjbyB1dGlsaXTDoXJpYSBwYXJhIHJlZ2lzdHJhciBldmVudG9zIGRlIGF1ZGl0b3JpYVxuYXN5bmMgZnVuY3Rpb24gbG9nRXZlbnQoeyB1c2VySWQsIGV2ZW50VHlwZSwgaXAsIHVzZXJBZ2VudCwgZGV0YWlscyB9OiB7IHVzZXJJZD86IHN0cmluZzsgZXZlbnRUeXBlOiBzdHJpbmc7IGlwPzogc3RyaW5nIHwgbnVsbDsgdXNlckFnZW50Pzogc3RyaW5nIHwgbnVsbDsgZGV0YWlscz86IGFueSB9KSB7XG4gIGlmICghQVVESVRfTE9HR0lOR19FTkFCTEVEKSByZXR1cm47XG4gIHRyeSB7XG4gICAgYXdhaXQgcHJpc21hLmF1ZGl0TG9nLmNyZWF0ZSh7XG4gICAgICBkYXRhOiB7XG4gICAgICAgIHVzZXJJZCxcbiAgICAgICAgZXZlbnRUeXBlLFxuICAgICAgICBpcDogaXAgfHwgbnVsbCxcbiAgICAgICAgdXNlckFnZW50OiB1c2VyQWdlbnQgfHwgbnVsbCxcbiAgICAgICAgZGV0YWlscyxcbiAgICAgIH0sXG4gICAgfSk7XG4gIH0gY2F0Y2ggKGVycikge1xuICAgIGNvbnNvbGUuZXJyb3IoXCJFcnJvIGFvIHJlZ2lzdHJhciBldmVudG8gZGUgYXVkaXRvcmlhOlwiLCBlcnIpO1xuICB9XG59XG5cbmNvbnN0IGNyZWRlbnRpYWxzU2NoZW1hID0gei5vYmplY3Qoe1xuICBlbWFpbDogei5zdHJpbmcoKS5lbWFpbCgpLFxuICBwYXNzd29yZDogei5zdHJpbmcoKS5taW4oNiksXG59KTtcblxuY29uc3QgYXV0aE9wdGlvbnMgPSB7XG4gIGFkYXB0ZXI6IFByaXNtYUFkYXB0ZXIocHJpc21hKSxcbiAgcHJvdmlkZXJzOiBbXG4gICAgQ3JlZGVudGlhbHNQcm92aWRlcih7XG4gICAgICBuYW1lOiBcIkVtYWlsIGUgU2VuaGFcIixcbiAgICAgIGNyZWRlbnRpYWxzOiB7XG4gICAgICAgIGVtYWlsOiB7IGxhYmVsOiBcIkVtYWlsXCIsIHR5cGU6IFwiZW1haWxcIiwgcGxhY2Vob2xkZXI6IFwic2V1QGVtYWlsLmNvbVwiIH0sXG4gICAgICAgIHBhc3N3b3JkOiB7IGxhYmVsOiBcIlNlbmhhXCIsIHR5cGU6IFwicGFzc3dvcmRcIiB9LFxuICAgICAgfSxcbiAgICAgIGFzeW5jIGF1dGhvcml6ZShjcmVkZW50aWFscykge1xuICAgICAgICBjb25zdCBwYXJzZWQgPSBjcmVkZW50aWFsc1NjaGVtYS5zYWZlUGFyc2UoY3JlZGVudGlhbHMpO1xuICAgICAgICBpZiAoIXBhcnNlZC5zdWNjZXNzKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiQ3JlZGVuY2lhaXMgaW52w6FsaWRhc1wiKTtcbiAgICAgICAgfVxuICAgICAgICBjb25zdCB7IGVtYWlsLCBwYXNzd29yZCB9ID0gcGFyc2VkLmRhdGE7XG4gICAgICAgIGNvbnN0IHVzZXIgPSBhd2FpdCBwcmlzbWEudXNlci5maW5kVW5pcXVlKHsgd2hlcmU6IHsgZW1haWwgfSB9KTtcblxuICAgICAgICBpZiAoIXVzZXIgfHwgIXVzZXIucGFzc3dvcmQpIHtcbiAgICAgICAgICBhd2FpdCBsb2dFdmVudCh7IGV2ZW50VHlwZTogXCJsb2dpbl9mYWlsZWRcIiwgZGV0YWlsczogeyBlbWFpbCB9IH0pO1xuICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlVzdcOhcmlvIG91IHNlbmhhIGludsOhbGlkb3NcIik7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgaXNWYWxpZCA9IGF3YWl0IGJjcnlwdC5jb21wYXJlKHBhc3N3b3JkLCB1c2VyLnBhc3N3b3JkKTtcbiAgICAgICAgaWYgKCFpc1ZhbGlkKSB7XG4gICAgICAgICAgYXdhaXQgbG9nRXZlbnQoeyB1c2VySWQ6IHVzZXIuaWQsIGV2ZW50VHlwZTogXCJsb2dpbl9mYWlsZWRcIiwgZGV0YWlsczogeyBlbWFpbCB9IH0pO1xuICAgICAgICAgIHRocm93IG5ldyBFcnJvcihcIlVzdcOhcmlvIG91IHNlbmhhIGludsOhbGlkb3NcIik7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICBpZDogdXNlci5pZCxcbiAgICAgICAgICBlbWFpbDogdXNlci5lbWFpbCxcbiAgICAgICAgICBuYW1lOiBgJHt1c2VyLmZpcnN0TmFtZX0gJHt1c2VyLmxhc3ROYW1lfWAsXG4gICAgICAgIH07XG4gICAgICB9LFxuICAgIH0pLFxuICAgIC4uLihwcm9jZXNzLmVudi5HT09HTEVfQ0xJRU5UX0lEICYmIHByb2Nlc3MuZW52LkdPT0dMRV9DTElFTlRfU0VDUkVUXG4gICAgICA/IFtHb29nbGVQcm92aWRlcih7XG4gICAgICAgICAgY2xpZW50SWQ6IHByb2Nlc3MuZW52LkdPT0dMRV9DTElFTlRfSUQhLFxuICAgICAgICAgIGNsaWVudFNlY3JldDogcHJvY2Vzcy5lbnYuR09PR0xFX0NMSUVOVF9TRUNSRVQhLFxuICAgICAgICAgIGF1dGhvcml6YXRpb246IHtcbiAgICAgICAgICAgIHBhcmFtczogeyBzY29wZTogXCJvcGVuaWQgZW1haWwgcHJvZmlsZVwiIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSldXG4gICAgICA6IFtdKSxcbiAgXSxcbiAgc2Vzc2lvbjoge1xuICAgIHN0cmF0ZWd5OiBcImp3dFwiIGFzIGNvbnN0LFxuICB9LFxuICBwYWdlczoge1xuICAgIHNpZ25JbjogXCIvbG9naW5cIixcbiAgICBlcnJvcjogXCIvbG9naW5cIiwgLy8gQSBww6FnaW5hIGRlIGVycm8gYWdvcmEgw6kgL2xvZ2luIGUgbyBlcnJvIMOpIHBhc3NhZG8gcG9yIHF1ZXJ5IHBhcmFtXG4gIH0sXG4gIGNhbGxiYWNrczoge1xuICAgIGFzeW5jIHNpZ25Jbih7IHVzZXIgfTogYW55KSB7XG4gICAgICBhd2FpdCBsb2dFdmVudCh7IHVzZXJJZDogdXNlcj8uaWQsIGV2ZW50VHlwZTogXCJsb2dpbl9zdWNjZXNzXCIgfSk7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9LFxuICAgIGFzeW5jIGp3dCh7IHRva2VuLCB1c2VyLCBhY2NvdW50IH06IGFueSkge1xuICAgICAgaWYgKGFjY291bnQgJiYgdXNlcikge1xuICAgICAgICB0b2tlbi5pZCA9IHVzZXIuaWQ7XG4gICAgICB9XG4gICAgICByZXR1cm4gdG9rZW47XG4gICAgfSxcbiAgICBhc3luYyBzZXNzaW9uKHsgc2Vzc2lvbiwgdG9rZW4gfTogYW55KSB7XG4gICAgICBpZiAodG9rZW4gJiYgc2Vzc2lvbi51c2VyKSB7XG4gICAgICAgIHNlc3Npb24udXNlci5pZCA9IHRva2VuLmlkIGFzIHN0cmluZztcbiAgICAgIH1cbiAgICAgIHJldHVybiBzZXNzaW9uO1xuICAgIH0sXG4gIH0sXG4gIGV2ZW50czoge1xuICAgIGFzeW5jIHNpZ25JbihtZXNzYWdlOiB7IHVzZXI6IGFueSB9KSB7XG4gICAgICBpZiAobWVzc2FnZS51c2VyKSB7XG4gICAgICAgIGF3YWl0IGxvZ0V2ZW50KHsgdXNlcklkOiBtZXNzYWdlLnVzZXIuaWQsIGV2ZW50VHlwZTogXCJsb2dpbl9ldmVudF9zdWNjZXNzXCIgfSk7XG4gICAgICB9XG4gICAgfSxcbiAgICBhc3luYyBzaWduT3V0KG1lc3NhZ2U6IHsgdG9rZW46IGFueSB9KSB7XG4gICAgICBpZiAobWVzc2FnZS50b2tlbikge1xuICAgICAgICBhd2FpdCBsb2dFdmVudCh7IHVzZXJJZDogbWVzc2FnZS50b2tlbi5zdWIsIGV2ZW50VHlwZTogXCJsb2dvdXRfZXZlbnRcIiB9KTtcbiAgICAgIH1cbiAgICB9LFxuICB9LFxufTtcblxuY29uc3QgaGFuZGxlciA9IE5leHRBdXRoKGF1dGhPcHRpb25zKTtcblxuZXhwb3J0IHsgaGFuZGxlciBhcyBHRVQsIGhhbmRsZXIgYXMgUE9TVCB9OyAiXSwibmFtZXMiOlsiTmV4dEF1dGgiLCJQcmlzbWFBZGFwdGVyIiwiUHJpc21hQ2xpZW50IiwiR29vZ2xlUHJvdmlkZXIiLCJDcmVkZW50aWFsc1Byb3ZpZGVyIiwiYmNyeXB0IiwieiIsInByaXNtYSIsIkFVRElUX0xPR0dJTkdfRU5BQkxFRCIsInByb2Nlc3MiLCJlbnYiLCJsb2dFdmVudCIsInVzZXJJZCIsImV2ZW50VHlwZSIsImlwIiwidXNlckFnZW50IiwiZGV0YWlscyIsImF1ZGl0TG9nIiwiY3JlYXRlIiwiZGF0YSIsImVyciIsImNvbnNvbGUiLCJlcnJvciIsImNyZWRlbnRpYWxzU2NoZW1hIiwib2JqZWN0IiwiZW1haWwiLCJzdHJpbmciLCJwYXNzd29yZCIsIm1pbiIsImF1dGhPcHRpb25zIiwiYWRhcHRlciIsInByb3ZpZGVycyIsIm5hbWUiLCJjcmVkZW50aWFscyIsImxhYmVsIiwidHlwZSIsInBsYWNlaG9sZGVyIiwiYXV0aG9yaXplIiwicGFyc2VkIiwic2FmZVBhcnNlIiwic3VjY2VzcyIsIkVycm9yIiwidXNlciIsImZpbmRVbmlxdWUiLCJ3aGVyZSIsImlzVmFsaWQiLCJjb21wYXJlIiwiaWQiLCJmaXJzdE5hbWUiLCJsYXN0TmFtZSIsIkdPT0dMRV9DTElFTlRfSUQiLCJHT09HTEVfQ0xJRU5UX1NFQ1JFVCIsImNsaWVudElkIiwiY2xpZW50U2VjcmV0IiwiYXV0aG9yaXphdGlvbiIsInBhcmFtcyIsInNjb3BlIiwic2Vzc2lvbiIsInN0cmF0ZWd5IiwicGFnZXMiLCJzaWduSW4iLCJjYWxsYmFja3MiLCJqd3QiLCJ0b2tlbiIsImFjY291bnQiLCJldmVudHMiLCJtZXNzYWdlIiwic2lnbk91dCIsInN1YiIsImhhbmRsZXIiLCJHRVQiLCJQT1NUIl0sInNvdXJjZVJvb3QiOiIifQ==\n//# sourceURL=webpack-internal:///(rsc)/./app/auth/[...nextauth]/route.ts\n");

/***/ })

};
;

// load runtime
var __webpack_require__ = require("../../../webpack-runtime.js");
__webpack_require__.C(exports);
var __webpack_exec__ = (moduleId) => (__webpack_require__(__webpack_require__.s = moduleId))
var __webpack_exports__ = __webpack_require__.X(0, ["vendor-chunks/next","vendor-chunks/next-auth","vendor-chunks/@babel","vendor-chunks/jose","vendor-chunks/openid-client","vendor-chunks/uuid","vendor-chunks/zod","vendor-chunks/oauth","vendor-chunks/@panva","vendor-chunks/preact-render-to-string","vendor-chunks/oidc-token-hash","vendor-chunks/bcryptjs","vendor-chunks/preact","vendor-chunks/object-hash","vendor-chunks/cookie","vendor-chunks/@next-auth"], () => (__webpack_exec__("(rsc)/./node_modules/next/dist/build/webpack/loaders/next-app-loader.js?name=app%2Fauth%2F%5B...nextauth%5D%2Froute&page=%2Fauth%2F%5B...nextauth%5D%2Froute&appPaths=&pagePath=private-next-app-dir%2Fauth%2F%5B...nextauth%5D%2Froute.ts&appDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff%2Fapp&pageExtensions=tsx&pageExtensions=ts&pageExtensions=jsx&pageExtensions=js&rootDir=%2FUsers%2Fviniciusalbino%2FDocuments%2FGitHub%2Fclausediff&isDev=true&tsconfigPath=tsconfig.json&basePath=&assetPrefix=&nextConfigOutput=&preferredRegion=&middlewareConfig=e30%3D!")));
module.exports = __webpack_exports__;

})();