#ifndef WIN_HTTP_REQUEST
#define WIN_HTTP_REQUEST

// Minimum Language Standard: ISO C++17 Standard (/std:c++17).

#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <versionhelpers.h>

// Same as Linker->Additional Dependencies->winhttp.lib
#pragma comment(lib, "winhttp")

#include "win_http_utils.hpp"


namespace win_http {

	using timeout_type = unsigned short;
	using http_status_type = unsigned short;
	using windows_error_type = DWORD;
	using headers_map = headers::headers_map;

	enum class return_code {
		success,			// No error- successful request.
		not_executed,		// Request not executed yet.
		invalid_url,		// URL is empty or invalid for some reason.
		win_http_error,		// Some sort of internal Windows HTTP API error.
		connect_error,		// Cannot connect to server when sending request.
		ssl_error,			// Some sort of issue related to SSL and certificates when sending request.
		send_recieve_error,	// Any other error when sending data to or receiving data from server.
		proxy_error,		// Error while resolving potential proxy.
		proxy_auth_fail,	// Proxy authentication failed due to bad or missing credentials.
		win_version_error,	// Unsupported Windows version (less than Win 8.1).
		memory_error,		// Memory allocation error.
	};

	enum class request_method {
		get,
		post,
		head,
		options,
		put,
		patch,
		del, // Can't use the term `delete`.
	};


	class request_parameters {
		return_code ret_value_; request_method request_method_; std::string url_; std::string user_agent_;
		headers_map request_headers_; std::vector<char> request_body_;
		timeout_type connection_timeout_; timeout_type send_timeout_; timeout_type response_timeout_;
		bool accept_compressed_; bool ignore_ssl_errors_;
		std::string proxy_user_; std::string proxy_password_;
		http_status_type http_status_; std::vector<char> response_body_; headers_map response_headers_;
		windows_error_type windows_error_;
	public:
		request_parameters() : ret_value_(return_code::not_executed), request_method_(request_method::get),
			user_agent_("Win-HTTP-Request"), connection_timeout_(0), send_timeout_(0), response_timeout_(0),
			accept_compressed_(true), ignore_ssl_errors_(true), http_status_(0), windows_error_(0) {}

		request_parameters& ret_value(const return_code& val) { ret_value_ = val; return *this; }
		return_code ret_value() const { return ret_value_; }

		request_parameters& method(const request_method& val) { request_method_ = val; return *this; }
		request_method method() const { return request_method_; }

		request_parameters& url(const std::string& val) { url_ = val; return *this; }
		std::string url() const { return url_; }

		request_parameters& user_agent(const std::string& val) { user_agent_ = val; return *this; }
		std::string user_agent() const { return user_agent_; }

		request_parameters& request_headers(const headers_map& val) { request_headers_ = val; return *this; }
		headers_map request_headers() const { return request_headers_; }

		request_parameters& request_body(const std::vector<char>& val) { request_body_ = val; return *this; }
		request_parameters& request_body(const std::string& val) { request_body_ = utils::to_char_vector(val); return *this; }
		std::vector<char> request_body() const { return request_body_; }

		// Timeouts are in seconds.
		request_parameters& connection_timeout(const timeout_type& val) { connection_timeout_ = val; return *this; }
		timeout_type connection_timeout() const { return connection_timeout_; }

		request_parameters& send_timeout(const timeout_type& val) { send_timeout_ = val; return *this; }
		timeout_type send_timeout() const { return send_timeout_; }

		request_parameters& response_timeout(const timeout_type& val) { response_timeout_ = val; return *this; }
		timeout_type response_timeout() const { return response_timeout_; }

		request_parameters& accept_compressed(const bool& val) { accept_compressed_ = val; return *this; }
		bool accept_compressed() const { return accept_compressed_; }

		// Set to true for self-signed certificates.
		request_parameters& ignore_ssl_errors(const bool& val) { ignore_ssl_errors_ = val; return *this; }
		bool ignore_ssl_errors() const { return ignore_ssl_errors_; }

		request_parameters& proxy_user(const std::string& val) { proxy_user_ = val; return *this; }
		std::string proxy_user() const { return proxy_user_; }

		request_parameters& proxy_password(const std::string& val) { proxy_password_ = val; return *this; }
		std::string proxy_password() const { return proxy_password_; }

		request_parameters& http_status(const http_status_type& val) { http_status_ = val; return *this; }
		http_status_type http_status() const { return http_status_; }

		request_parameters& response_body(const std::vector<char>& val) { response_body_ = val; return *this; }
		request_parameters& response_body(const std::string& val) { response_body_ = utils::to_char_vector(val); return *this; }
		template<class T>
		typename std::enable_if<std::is_same<T, std::string>::value, T>::type
		response_body() const { return utils::from_char_vector(response_body_); }
		template<typename T>
		typename std::enable_if<std::is_same<T, std::vector<char>>::value, T>::type
		response_body() const { return response_body_; }

		request_parameters& response_headers(const headers_map& val) { response_headers_ = val; return *this; }
		headers_map response_headers() { return response_headers_; }

		request_parameters& windows_error(const windows_error_type& val) { windows_error_ = val; return *this; }
		windows_error_type windows_error() const { return windows_error_; }
	};

	DWORD choose_auth_scheme(DWORD supported_schemes);


	return_code make_http_request(request_parameters& params) {
		// Complex code is heavily based on examples provided by MS.

		::SetLastError(0);

		// Define variables that may need to be cleaned up at end.
		HINTERNET h_session = nullptr, h_connect = nullptr, h_request = nullptr;
		BYTE* response_buffer = nullptr;
		BYTE* part_buffer = nullptr;

		// Calling this lambda when it is desired to retunr from function will ensure proper
		// cleanup prior to actual return.
		auto exit_function = [&params, &h_session, &h_connect, &h_request, &response_buffer, &part_buffer](const return_code& ret_val) {
			// Close any open WinHTTP handles.
			if (h_request)
				::WinHttpCloseHandle(h_request);
			if (h_connect)
				::WinHttpCloseHandle(h_connect);
			if (h_session)
				::WinHttpCloseHandle(h_session);
			// Delete any lingering buffers.
			if (part_buffer) {
				free(part_buffer);
				part_buffer = nullptr;
			}
			if (response_buffer) {
				free(response_buffer);
				response_buffer = nullptr;
			}
			params.ret_value(ret_val);
			params.windows_error(::GetLastError());
			return ret_val;
		};

		// Reset members of struct used for output results.
		params.http_status(0);
		params.response_body(std::vector<char>());
		params.response_headers(headers_map());
		params.windows_error(0);

		// Check for unsupported Windows version (less than Win 8.1)
		if (!::IsWindows8Point1OrGreater())
			return exit_function(return_code::win_version_error);

		// Determine request method and whether or not to get response body.
		// Default would be GET.
		std::wstring method = L"GET";
		bool has_request_body = false;
		bool get_response_body = true;

		if (request_method::get == params.method()) {
			method = L"GET";
			has_request_body = false;
			get_response_body = true;
		}
		else if (request_method::post == params.method()) {
			method = L"POST";
			has_request_body = true;
			get_response_body = true;
		}
		else if (request_method::head == params.method()) {
			method = L"HEAD";
			has_request_body = false;
			get_response_body = false;
		}
		else if (request_method::options == params.method()) {
			method = L"OPTIONS";
			has_request_body = false;
			get_response_body = false;
		}
		else if (request_method::put == params.method()) {
			method = L"PUT";
			has_request_body = true;
			get_response_body = false;
		}
		else if (request_method::patch == params.method()) {
			method = L"PATCH";
			has_request_body = true;
			get_response_body = false;
		}
		else if (request_method::del == params.method()) {
			method = L"DELETE";
			has_request_body = true;
			get_response_body = false;
		}

		// This will be used over and over again for determing progress through function and if an error has occurred.
		BOOL results = false;

		std::wstring url = utils::to_wide(params.url());
		if (0 == url.length())
			return exit_function(return_code::invalid_url);

		// Parses the URL into various required components.
		URL_COMPONENTS urlComp;
		std::memset(&urlComp, 0, sizeof(urlComp));
		urlComp.dwStructSize = sizeof(urlComp);
		urlComp.dwHostNameLength = (DWORD)-1;
		urlComp.dwUrlPathLength = (DWORD)-1;
		urlComp.dwExtraInfoLength = (DWORD)-1;
		results = ::WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp);
		if (!results)
			return exit_function(return_code::invalid_url);

		// Set variables based on cracked URL to pass to WinHTTP functions.
		INTERNET_SCHEME	scheme = urlComp.nScheme; // INTERNET_SCHEME_HTTP or INTERNET_SCHEME_HTTPS.
		INTERNET_PORT port = urlComp.nPort;
		std::wstring path = std::wstring(urlComp.lpszUrlPath);
		std::wstring extra = std::wstring(urlComp.lpszExtraInfo);

		// WinHttpCrackUrl fails to properly isolate host name, so we most isolate it by copying only the correct part of it.
		std::wstring host = std::wstring(urlComp.lpszHostName).substr(0, urlComp.dwHostNameLength);
		if (0 == host.length())
			return exit_function(return_code::invalid_url);

// Proxy handling.
// WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY is only available in >= Win 8.1.
#ifdef WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
		h_session = ::WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
#else
		h_session = ::WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
#endif

		// Check for error from WinHttpOpen.
		if (nullptr == h_session)
			return exit_function(return_code::win_http_error);

		// Set the various timeouts.
		// Convert timeouts to milliseconds.
		::WinHttpSetTimeouts(h_session, 0, params.connection_timeout() * 1000, params.send_timeout() * 1000, params.response_timeout() * 1000);

		h_connect = ::WinHttpConnect(h_session, host.c_str(), port, 0);

		// Check for error from WinHttpConnect.
		if (nullptr == h_connect)
			return exit_function(return_code::win_http_error);

		// Create an HTTP request handle passing in cracked URL, HTTP method, and path variables and settings related to HTTP scheme.
		DWORD flags = (INTERNET_SCHEME_HTTPS == scheme ? WINHTTP_FLAG_REFRESH | WINHTTP_FLAG_SECURE : WINHTTP_FLAG_REFRESH);
		h_request = ::WinHttpOpenRequest(h_connect, method.c_str(), path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

		// Check for error from WinHttpOpenRequest.
		if (nullptr == h_request)
			return exit_function(return_code::win_http_error);

		// If specified, set to accept compressed response.
		// Only available in >= Win 8.1.
		// BIG NOTE: setting compression to true can very likely cause the following
		// two response headers to be stripped out of response:
		// Content-length, Content-Encoding. Evil!
		// Don't error check this- no need.
#ifdef WINHTTP_OPTION_DECOMPRESSION
		if (params.accept_compressed() && ::IsWindows8Point1OrGreater()) {
			DWORD comp_flag = WINHTTP_DECOMPRESSION_FLAG_ALL;
			::WinHttpSetOption(h_request, WINHTTP_OPTION_DECOMPRESSION, &comp_flag, sizeof(DWORD));
		}
#endif

		// Set User Agent.
		// Don't error check this- no need.
		std::wstring user_agent = utils::to_wide(params.user_agent());
		::WinHttpSetOption(h_request, WINHTTP_OPTION_USER_AGENT, (LPVOID)user_agent.c_str(), (DWORD)user_agent.length());

		// If specified, ignore issues with SSL certificates.
		// Don't error check this- no need.
		if (params.ignore_ssl_errors()) {
			DWORD sec_options = SECURITY_FLAG_IGNORE_UNKNOWN_CA
				| SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
				| SECURITY_FLAG_IGNORE_CERT_CN_INVALID
				| SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
			::WinHttpSetOption(h_request, WINHTTP_OPTION_SECURITY_FLAGS, &sec_options, sizeof(DWORD));
		}

		// Request headers.
		if (params.request_headers().size() > 0) {
			std::wstring req_headers = utils::to_wide(headers::to_string(params.request_headers()));
			// Add additional request headers if specified. If the header with same name exists, replace it, else add it new.
			// Malformed headers are ignored.
			// Don't error check this- no need.
			if (req_headers.length() > 0)
				::WinHttpAddRequestHeaders(h_request, &req_headers[0], req_headers.length(), WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
		}

		// The following code is based largely on example code provided by MS.

		// Handles potential proxy authentication.
		// We aren't going to handle server HTTP auth via WinHTTP, only proxy auth.
		// If user needs that, they can manually add auth headers to the request.
		// We have to call WinHttpSendRequest in a loop in case there is a proxy server and it needs authentication.

		// This can be confusing to understand but is very similar logic to what MS presents!!!

		DWORD http_status = 0;
		DWORD count_407 = 0;
		DWORD proxy_auth_scheme = 0;
		bool done_sending = false;
		std::wstring proxy_user = utils::to_wide(params.proxy_user());
		std::wstring proxy_password = utils::to_wide(params.proxy_password());

		while (!done_sending) {
			// If there is a proxy authentication challenge from WinHttpSendRequest, set those credentials (if specified) before
			// each additional WinHttpSendRequest because the proxy may require re-authentication for a redirect.

			// If user name and password are nullptr, then an default credentials set in Windows (if there are any) will be used.
			if (0 != proxy_auth_scheme) // First time, this will be 0. Value is set later.
				::WinHttpSetCredentials(h_request, WINHTTP_AUTH_TARGET_PROXY, proxy_auth_scheme,
					(proxy_user.length() > 0) ? proxy_user.c_str() : nullptr,
					(proxy_password.length() > 0) ? proxy_password.c_str() : nullptr, nullptr);

			// Send the request optionally specifying a request body if it is set.
			// !!! Request bodies use bytes, not wide chars.
			if (has_request_body)
				results = ::WinHttpSendRequest(h_request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)&params.request_body()[0], (DWORD)params.request_body().size(), (DWORD)params.request_body().size(), 0);
			else
				results = ::WinHttpSendRequest(h_request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

			// If there are results from WinHttpSendRequest, check the response.
			if (results)
				results = ::WinHttpReceiveResponse(h_request, NULL);

			// If no good response, use GetLastError() to decide what to do.
			if (!results) {
				// In case of ERROR_WINHTTP_RESEND_REQUEST error, resend the request. proxy_auth_scheme is not modified.
				if (ERROR_WINHTTP_RESEND_REQUEST == ::GetLastError())
					continue; // Go back and try again.
				else {
					// Most likely a network error such or no internet connection. So we can bail out.
					int err = ::GetLastError();
					if (ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED == err || ERROR_WINHTTP_SECURE_FAILURE == err) // SSL cert related issues.
						return exit_function(return_code::ssl_error);
					else if (ERROR_WINHTTP_CANNOT_CONNECT == err || ERROR_WINHTTP_CONNECTION_ERROR == err
						|| ERROR_WINHTTP_TIMEOUT == err || ERROR_WINHTTP_NAME_NOT_RESOLVED == err) // Actual connection to server issues.
						return exit_function(return_code::connect_error);
					else // Any other issues.
						return exit_function(return_code::send_recieve_error);
				}
			}

			// If a good response, get the HTTP status to see if we need to resend with proxy authentication. Do it twice.
			// If authentication failed bail out.
			if (results) {
				// Get HTTP status code.
				DWORD status_size = sizeof(http_status);
				::WinHttpQueryHeaders(h_request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &http_status, &status_size, WINHTTP_NO_HEADER_INDEX);
				params.http_status((http_status_type)http_status);

				// Check if the proxy requires authentication (status = 407).
				if (407 == http_status) {
					// If done 2 times, bail out.
					if (2 == count_407)
						return exit_function(return_code::proxy_auth_fail);
					else {
						count_407++;
						DWORD supported_schemes;
						DWORD first_scheme;
						DWORD target;

						// Obtain the supported and preferred schemes.
						results = ::WinHttpQueryAuthSchemes(h_request, &supported_schemes, &first_scheme, &target);

						// Check for error from WinHttpQueryAuthSchemes.
						if (!results)
							return exit_function(return_code::proxy_auth_fail);
						else {
							proxy_auth_scheme = choose_auth_scheme(supported_schemes);
							continue; // proxy_auth_scheme is now assigned, so try loop again.
						}
					}
				}
				else {
					// Failed DNS lookup. Bad Gateway or Gateway Timeout- something along those lines. Bail out.
					if (502 == http_status || 542 == http_status)
						return exit_function(return_code::connect_error);

					done_sending = true;
				}
			}

			// Yet another check needs to be done.
			if (!results)
				return exit_function(return_code::proxy_auth_fail);
		}

		// We got through sending request.

		// Get response headers.
		// Call once to get buffer size. Don't check return.
		DWORD resp_headers_size = 0;
		::WinHttpQueryHeaders(h_request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &resp_headers_size, WINHTTP_NO_HEADER_INDEX);
		// Call again to get the actual content into buffer.
		// Use std::wstring for buffer.
		if (resp_headers_size > 0) {
			std::wstring resp_headers;
			resp_headers.resize(static_cast<std::size_t>(resp_headers_size), L'\0');
			::WinHttpQueryHeaders(h_request, WINHTTP_QUERY_RAW_HEADERS_CRLF, WINHTTP_HEADER_NAME_BY_INDEX, (LPVOID)&resp_headers[0], &resp_headers_size, WINHTTP_NO_HEADER_INDEX);
			// Skip first header when parsing- it is HTTP status, not a true header.
			params.response_headers(headers::from_string(utils::from_wide(resp_headers.substr(resp_headers.find_first_of(L'\n') + 1))));
		}

		// If no response body is expected based on request method (see beginning of function),
		// then skip the rest of processing.
		if (!get_response_body)
			return exit_function(return_code::success);

		// Now read response body.
		// Response body will actually be in bytes and not wide characters!

		// WinHTTP doesn't actually tell you the full size of the response- it only tell you in parts.
		// So we have to allocate a buffer of a certain size for the cumulative response body
		// and dynamically resize it as necessary.

		DWORD allocated = 8196;
		DWORD total_read = 0;
		DWORD size_to_read = 0;
		DWORD size_read = 0;

		// Create buffer for cumulative response body.
		response_buffer = (BYTE*)malloc(allocated * sizeof(BYTE));
		if (!response_buffer)
			return exit_function(return_code::memory_error);
		memset(response_buffer, 0, allocated * sizeof(BYTE));

		do {
			// Check for available data.
			size_to_read = 0;
			if (::WinHttpQueryDataAvailable(h_request, &size_to_read)) {
				// No more available data.
				if (0 == size_to_read)
					break;

				// Read the part data into a temp buffer. It is bytes!!!
				part_buffer = (BYTE*)malloc(size_to_read * sizeof(BYTE));
				if (!part_buffer)
					return exit_function(return_code::memory_error);

				memset(part_buffer, 0, size_to_read);

				::WinHttpReadData(h_request, (LPVOID)part_buffer, size_to_read, &size_read);

				DWORD last = total_read;
				total_read += size_to_read;

				// Check if we need to resize cumulative buffer.
				if (total_read > allocated) {
					DWORD new_read = 0;
					DWORD def_size = 8192;

					if (total_read > (last + def_size))
						new_read = total_read;
					else
						new_read = last + def_size;
					if (0 == new_read)
						return exit_function(return_code::memory_error);

					BYTE* new_buffer = (BYTE*)realloc(response_buffer, new_read * sizeof(BYTE));
					if (!new_buffer)
						return exit_function(return_code::memory_error);

					allocated = new_read;

					response_buffer = new_buffer;
					memset(response_buffer + last, 0, (allocated - last) * sizeof(BYTE));
				}

				// Append part_buffer to cumulative buffer then delete part_buffer.
				memmove(&response_buffer[last], part_buffer, size_to_read * sizeof(BYTE));

				if (part_buffer) {
					free(part_buffer);
					part_buffer = nullptr;
				}

				// This condition should never be reached since WinHttpQueryDataAvailable
				// reported that there are bits to read. But is sanity check MS shows in examples.
				if (!size_read)
					break;
			}
		} while (size_to_read > 0);

		// If no errors thus far, copy to params response body.
		if (total_read > 0) {
			if (response_buffer) {
				params.response_body(std::vector<char>(response_buffer, response_buffer + total_read));
				//free(response_buffer);
				//response_buffer = nullptr;
			}
		}

		// Made it through with no errors!
		return exit_function(return_code::success);
	}


	// Returns a prioritized authentication scheme from available ones.
	DWORD choose_auth_scheme(DWORD supported_schemes) {
		// It is the server's responsibility only to accept
		// authentication schemes that provide a sufficient
		// level of security to protect the servers resources.
		//
		// The client is also obligated only to use an authentication
		// scheme that adequately protects its username and password.
		//
		// Thus, because Basic authentication exposes the client's username
		// and password to anyone monitoring the connection, it is lowest
		// in priority.

		if (supported_schemes & WINHTTP_AUTH_SCHEME_NEGOTIATE)
			return WINHTTP_AUTH_SCHEME_NEGOTIATE;
		else if (supported_schemes & WINHTTP_AUTH_SCHEME_NTLM)
			return WINHTTP_AUTH_SCHEME_NTLM;
		else if (supported_schemes & WINHTTP_AUTH_SCHEME_PASSPORT)
			return WINHTTP_AUTH_SCHEME_PASSPORT;
		else if (supported_schemes & WINHTTP_AUTH_SCHEME_DIGEST)
			return WINHTTP_AUTH_SCHEME_DIGEST;
		else if (supported_schemes & WINHTTP_AUTH_SCHEME_BASIC)
			return WINHTTP_AUTH_SCHEME_BASIC;
		else
			return 0;
	}

} // End namespace

#endif /*WIN_HTTP_REQUEST */