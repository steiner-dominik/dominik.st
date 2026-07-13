let securityHeaders = {
//	"Content-Security-Policy": "report-to csp-endpoint; report-uri https://steiner.report-uri.com/r/d/csp/enforce; upgrade-insecure-requests; default-src 'none'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-hashes' 'sha256-YFCzJYJPywguDyTjs2n1NnIobvLm0ceubJsVHxaFQMI='; font-src 'self'; img-src 'self'; connect-src 'self' https://cloudflareinsights.com; base-uri 'self'",
	"Content-Security-Policy": "report-to csp-endpoint; report-uri https://steiner.report-uri.com/r/d/csp/enforce; upgrade-insecure-requests; default-src 'none'; script-src 'self' https://static.cloudflareinsights.com; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self' https://cloudflareinsights.com; base-uri 'self'",
	"X-XSS-Protection": "1; mode=block",
	"X-Frame-Options": "SAMEORIGIN",
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy": "strict-origin-when-cross-origin",
//	"Feature-Policy": "geolocation 'none'; midi 'none'; sync-xhr 'self'; microphone 'none'; camera 'none'; magnetometer 'none'; gyroscope 'none'; fullscreen 'self'; payment 'none'",
	"Permissions-Policy": "accelerometer=(), bluetooth=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
	"Report-To": '{"group":"default","max_age":31536000,"endpoints":[{"url":"https://steiner.report-uri.com/a/d/g"}],"include_subdomains":true},{"group":"csp-endpoint","max_age":31536000,"endpoints":[{"url":"https://steiner.report-uri.com/r/d/csp/enforce"}],"include_subdomains":true}',
	"NEL": '{"report_to":"default","max_age":31536000,"include_subdomains":true}',
}

let sanitiseHeaders = {
	"Server" : "cloudflare",
}

let removeHeaders = [
	"Public-Key-Pins",
	"X-Powered-By",
	"X-AspNet-Version",
	"x-ms-version",
	"x-ms-request-id",
	"x-ms-blob-type",
	"x-ms-lease-status",
]

addEventListener('fetch', event => {
	event.respondWith(addHeaders(event.request))
})

async function addHeaders(req) {
	let response = await fetch(req)
	let newHdrs = new Headers(response.headers)

/*
	if (newHdrs.has("Content-Type") && !newHdrs.get("Content-Type").includes("text/html")) {
		return new Response(response.body , {
			status: response.status,
			statusText: response.statusText,
			headers: newHdrs
		})
	}
*/

	let setHeaders = Object.assign({}, securityHeaders, sanitiseHeaders)

	Object.keys(setHeaders).forEach(name => {
		newHdrs.set(name, setHeaders[name]);
	})

	removeHeaders.forEach(name => {
		newHdrs.delete(name)
	})

	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: newHdrs
	})
}