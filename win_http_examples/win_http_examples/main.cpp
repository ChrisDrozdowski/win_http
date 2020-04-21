#include <iostream>

#include "../../win_http/win_http_request.hpp"

void get_example() {
	std::string the_url = "https://httpbin.org/get";

	// win_http is std::string-based. But there are utility functions to convert
	// from and to std::wstring. See list at the end of this function.

	// Define the request by creating and populating an instance of win_http::request_parameters.

	win_http::request_parameters params;
	params.url(the_url);
	params.method(win_http::request_method::get);
	params.user_agent("win_http_examples");

	// Class derived from std::unordered_multimap with case-insensitive keys to handle request and response headers.
	win_http::headers_map request_headers;
	request_headers.insert({"Accept", "application/json"});
	request_headers.insert({ "X-Custom-Header", "some-value" });

	params.request_headers(request_headers);

	// Observe that setters can be chained.
	// Timeouts are in seconds. Default is 0 - no timeout.
	params.connection_timeout(30).send_timeout(30).response_timeout(30);
	params.accept_compressed(true); // Default is true.
	params.ignore_ssl_errors(true); // Default is true.
	//params.proxy_user("p_user").proxy_password("p_pwd"); // Enable and change if necessary.

	// Run the request.
	win_http::return_code code = win_http::make_http_request(params);

	// Get the results of the request.
	
	// Getters for all properties are named same as setters but don't accept parameters.
	// A few getter examples:
	std::string url = params.url();
	win_http::request_method meth = params.method();
	std::string ua = params.user_agent();
	win_http::timeout_type conn_to = params.connection_timeout();

	// Get info related to actual response.
	win_http::http_status_type status = params.http_status();
	win_http::windows_error_type win_error = params.windows_error();
	win_http::headers_map response_headers = params.response_headers();
	std::vector<char> response_body_raw = params.response_body<std::vector<char>>(); // Raw response body. Templated.
	std::string response_body_str = params.response_body<std::string>(); // Response body as string. Templated

	// Dump response info.
	std::cout << "Return code: " << static_cast<int>(code) << "\n";
	std::cout << "HTTP status: " << status << "\n";
	std::cout << "Response headers: " << "\n";
	for (const auto h : response_headers) {
		std::cout << h.first << ":" << h.second << "\n";
	}
	std::cout << "Content: " << response_body_str << "\n";

	/* Useful utility functions:
	std::wstring win_http::utils::to_wide(const std::string & str);
	std::string win_http::utils::from_wide(const std::wstring & wstr);
	std::string win_http::utils::get_http_time(const SYSTEMTIME & st);
	std::string win_http::utils::get_http_time(); // For current date time.
	*/
}


void post_example() {

	// Please see get_example() for a more thorough example!!!

	std::string the_url = "https://httpbin.org/post";

	win_http::request_parameters params;
	params.url(the_url);
	params.method(win_http::request_method::post);

	win_http::headers_map request_headers;
	request_headers.insert({ "Content-Type", "application/x-www-form-urlencoded" });

	params.request_headers(request_headers);

	params.request_body("param1=value_1&param2=value_2&param3=value_3");

	win_http::return_code code = win_http::make_http_request(params);

	win_http::http_status_type status = params.http_status();
	win_http::windows_error_type win_error = params.windows_error();
	win_http::headers_map response_headers = params.response_headers();
	std::string response_body_str = params.response_body<std::string>();

	std::cout << "Return code: " << static_cast<int>(code) << "\n";
	std::cout << "HTTP status: " << status << "\n";
	std::cout << "Response headers: " << "\n";
	for (const auto h : response_headers) {
		std::cout << h.first << ":" << h.second << "\n";
	}
	std::cout << "Content: " << response_body_str << "\n";
}


// For memory leak testing.
//#define _CRTDBG_MAP_ALLOC
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif

int main() {
// For memory leak testing. If memory leak, message in output window.
#ifdef _CRTDBG_MAP_ALLOC
	::_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

	// Study the GET example for thourough walk through of win_http.
	std::cout << "GET Request Example\n===================\n";
	get_example();
	std::cout << "POST Request Example\n====================\n";
	post_example();
}
