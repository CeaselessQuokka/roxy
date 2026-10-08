-- Roblox API stand-ins for type checking the public site's Luau examples with luau-analyze.
--
-- luau-analyze (github.com/luau-lang/luau) knows the Luau standard library (string, table, math, os, pcall,
-- tonumber, print...) but not Roblox's globals. test_luau_examples.py pastes this file right after each example's
-- `--!strict` line, so `game`, `task` and `warn` exist with the same types Roblox gives them. The shapes follow
-- the Roblox type definitions that luau-lsp ships (scripts/globalTypes.d.luau in JohnnyMorganz/luau-lsp):
-- HttpRequestOptions, HttpResponseData (note `Body: string?`), the HttpService methods, `task` and `warn`.
-- Overloads (`GetService("HttpService")` returning HttpService) are written as an intersection of function types.
-- Only what the examples use is declared; a call to anything else is reported, which is the point.

type Secret = { __secretTag: never } -- an opaque value from HttpService:GetSecret; never a plain string

type HttpRequestOptions = {
	Url: string | Secret,
	Method: "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH" | nil,
	Headers: { [string]: string | Secret }?,
	Body: string?,
	Compress: unknown?,
}

type HttpResponseData = {
	Success: boolean,
	StatusCode: number,
	StatusMessage: string,
	Headers: { [string]: string },
	Body: string?,
}

type HttpService = {
	GetAsync: (self: HttpService, url: any, nocache: boolean?, headers: any) -> string,
	PostAsync: (self: HttpService, url: any, data: string, contentType: unknown?, compress: boolean?, headers: any) -> string,
	RequestAsync: (self: HttpService, options: HttpRequestOptions) -> HttpResponseData,
	JSONDecode: (self: HttpService, input: string) -> any,
	JSONEncode: (self: HttpService, input: any) -> string,
	UrlEncode: (self: HttpService, input: string) -> string,
}

type ModuleScript = { ClassName: "ModuleScript", Name: string }

type ServerScriptService = { RoxyClient: ModuleScript }

type DataModel = {
	GetService: ((self: DataModel, className: "HttpService") -> HttpService)
		& ((self: DataModel, className: "ServerScriptService") -> ServerScriptService),
}

local game: DataModel = (nil :: any)

local task: {
	wait: (duration: number?) -> number,
	cancel: (thread: thread) -> (),
} = (nil :: any)

local function warn<T...>(...: T...): () end
